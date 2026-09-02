using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

// Commercial polish (PR #23 — "LL / product" layer):
//
//   Licensing   — HMAC-SHA256-signed JSON license files. Offline validation
//                 (no phoning home). Supports Community / Pro / Enterprise
//                 SKUs and per-feature entitlements.
//
//   ProductInfo — product name, version, build date, brand string.
//
//   UpdateCheck — pulls a signed release manifest from a vendor-controlled
//                 HTTPS URL, verifies the signature, exposes the latest
//                 version + download URL. No auto-install yet — the caller
//                 (CLI or GUI) decides whether to prompt.
//
//   RestServer  — minimal HttpListener-based REST server that exposes
//                 POST /scan (multipart upload OR local path) and GET /health.
//                 Requires a valid license (Pro or Enterprise) to start.
//                 Zero new dependencies — uses only System.Net.HttpListener.

namespace AntiStealerOneExe
{
    // ------------------------------------------------------------------
    // ProductInfo
    // ------------------------------------------------------------------
    public static class ProductInfo
    {
        public const string Name      = "AntiStealer";
        public const string Vendor    = "whysgit";
        public const string Version   = "1.0.0";
        public const string Copyright = "© whysgit. All rights reserved.";
        public const string Website   = "https://github.com/whysgit/antistealer";
        public static readonly DateTime BuildDate = new(2026, 04, 23, 0, 0, 0, DateTimeKind.Utc);

        public static string Banner(License? lic = null)
        {
            var sku = lic?.Sku ?? "community";
            var cust = string.IsNullOrEmpty(lic?.Customer) ? "Unlicensed" : lic!.Customer!;
            return $"{Name} {Version} ({sku}) — {cust}";
        }
    }

    // ------------------------------------------------------------------
    // Licensing
    // ------------------------------------------------------------------
    public enum LicenseSku
    {
        Community,        // free, limited concurrency, no REST, no pro report
        Pro,              // single-seat, all detectors, REST API allowed
        Enterprise,       // org-wide, watch-folder, custom rules server
    }

    public sealed class License
    {
        [JsonPropertyName("customer")]  public string? Customer { get; set; }
        [JsonPropertyName("sku")]       public string  Sku      { get; set; } = "community";
        [JsonPropertyName("issued")]    public DateTime Issued  { get; set; }
        [JsonPropertyName("expires")]   public DateTime Expires { get; set; }
        [JsonPropertyName("seats")]     public int     Seats    { get; set; } = 1;
        [JsonPropertyName("features")]  public List<string> Features { get; set; } = new();
        // Legacy HMAC-SHA256 signature (hex-encoded). Retained for backward compatibility
        // with licences issued before the Ed25519 migration (Section 13.5).
        [JsonPropertyName("signature")] public string? Signature { get; set; }
        // Section 13.5 — preferred signature: Ed25519 detached signature (base64).
        // Verifiers try Ed25519 first; if absent, fall back to the HMAC field.
        [JsonPropertyName("signatureEd25519")] public string? SignatureEd25519 { get; set; }

        [JsonIgnore]
        public LicenseSku SkuEnum => Sku?.ToLowerInvariant() switch
        {
            "pro"        => LicenseSku.Pro,
            "enterprise" => LicenseSku.Enterprise,
            _            => LicenseSku.Community,
        };

        [JsonIgnore] public bool IsExpired => DateTime.UtcNow > Expires;

        public bool Has(string feature) =>
            Features != null && Features.Contains(feature, StringComparer.OrdinalIgnoreCase);
    }

    public static class LicenseVerifier
    {
        private static readonly JsonSerializerOptions JsonOpts = JsonOptionsRegistry.CamelCaseIndented;

        // Section 13.5 — legacy HMAC key, retained so licences issued before
        // the Ed25519 migration still validate. Replace with your build-time
        // secret. The Ed25519 vendor public key replaces this for new
        // licences (see DefaultEd25519PublicKeyBase64 below).
        public const string DefaultPublicKey = "ANTISTEALER-DEV-PLACEHOLDER-REPLACE-BEFORE-SHIP";

        // Section 13.5 — vendor-public Ed25519 verification key, base64.
        // This is *only* the public key; the matching private seed must be
        // kept on the signing host (build pipeline secret). The placeholder
        // here is a 32-byte all-zero key, which by definition rejects every
        // signature — production builds embed the real public key via
        // `dotnet build /p:VendorEd25519PublicKey=...` (see PR 3 / 13.4).
        public const string DefaultEd25519PublicKeyBase64 =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        // ----------------------------------------------------------------
        // Section 13.4 — vendor-key embed pipeline.
        //
        // At runtime callers that don't want to hard-code the placeholder
        // public key can resolve "the right key for this build" through
        // these helpers. The resolution order is intentional:
        //
        //   1. Process env var (ANTISTEALER_LICENSE_HMAC_KEY /
        //      ANTISTEALER_LICENSE_ED25519_PUBKEY). Highest priority so
        //      operators can override without rebuilding — useful for
        //      staged rollouts and local development.
        //   2. Embedded resource (Commercial.LicenseHmacKey.txt /
        //      Commercial.LicenseEd25519PublicKey.txt). Baked into the
        //      assembly via the build pipeline (see CI's "embed-keys"
        //      step). This is what production binaries ship with.
        //   3. The compiled-in DefaultPublicKey / DefaultEd25519PublicKeyBase64
        //      placeholders. Reaching this branch in a production build
        //      means the embed step was skipped — the verifier will
        //      reject all real licences (fail-closed).
        // ----------------------------------------------------------------
        public const string EnvHmacKey            = "ANTISTEALER_LICENSE_HMAC_KEY";
        public const string EnvEd25519PublicKey   = "ANTISTEALER_LICENSE_ED25519_PUBKEY";
        public const string ResourceHmacKey       = "AntiStealerOneExe.Embedded.LicenseHmacKey.txt";
        public const string ResourceEd25519Key    = "AntiStealerOneExe.Embedded.LicenseEd25519PublicKey.txt";

        public static string ResolveHmacKey()
        {
            var fromEnv = Environment.GetEnvironmentVariable(EnvHmacKey);
            if (!string.IsNullOrWhiteSpace(fromEnv)) return fromEnv.Trim();

            var fromResource = ReadEmbeddedResource(ResourceHmacKey);
            if (!string.IsNullOrWhiteSpace(fromResource)) return fromResource.Trim();

            return DefaultPublicKey;
        }

        public static string ResolveEd25519PublicKeyBase64()
        {
            var fromEnv = Environment.GetEnvironmentVariable(EnvEd25519PublicKey);
            if (!string.IsNullOrWhiteSpace(fromEnv)) return fromEnv.Trim();

            var fromResource = ReadEmbeddedResource(ResourceEd25519Key);
            if (!string.IsNullOrWhiteSpace(fromResource)) return fromResource.Trim();

            return DefaultEd25519PublicKeyBase64;
        }

        // True when the resolved key is still the dev placeholder. Callers
        // that want a "fail-closed in production" check can assert this is
        // false at startup.
        public static bool IsUsingPlaceholderKeys()
            =>     ResolveHmacKey()             == DefaultPublicKey
                && ResolveEd25519PublicKeyBase64() == DefaultEd25519PublicKeyBase64;

        private static string? ReadEmbeddedResource(string name)
        {
            try
            {
                var asm = typeof(LicenseVerifier).Assembly;
                using var s = asm.GetManifestResourceStream(name);
                if (s == null) return null;
                using var r = new StreamReader(s);
                return r.ReadToEnd();
            }
            catch
            {
                return null;
            }
        }

        public static License Sign(License lic, string hmacKey)
        {
            lic.Signature = null;
            lic.SignatureEd25519 = null;
            var payload = JsonSerializer.Serialize(lic, JsonOpts);
            lic.Signature = Hmac(payload, hmacKey);
            return lic;
        }

        // Section 13.5 — preferred signing API. Produces an Ed25519 detached
        // signature (base64) and clears the legacy HMAC field. Callers can
        // optionally also call Sign(...) to keep an HMAC fallback for
        // backward compatibility.
        public static License SignEd25519(License lic, ReadOnlySpan<byte> privateKey)
        {
            lic.Signature = null;
            lic.SignatureEd25519 = null;
            var payload = JsonSerializer.Serialize(lic, JsonOpts);
            var sig = Ed25519Crypto.Sign(Encoding.UTF8.GetBytes(payload), privateKey);
            lic.SignatureEd25519 = Convert.ToBase64String(sig);
            return lic;
        }

        public static bool Verify(License lic, string hmacKey, out string reason)
            => Verify(lic, hmacKey, ed25519PublicKeyBase64: null, out reason);

        // Section 13.5 — verification with optional Ed25519 vendor public key.
        // Verification order:
        //   1. If a base64 Ed25519 public key is supplied AND the licence carries
        //      a SignatureEd25519, that signature is verified. Failure here is
        //      fatal — we do not silently fall back to the (weaker) HMAC.
        //   2. Otherwise we fall back to the legacy HMAC path. This keeps old
        //      licences working without forcing a re-issue.
        public static bool Verify(License lic, string hmacKey, string? ed25519PublicKeyBase64, out string reason)
        {
            reason = "";
            if (lic == null) { reason = "null license"; return false; }
            if (lic.IsExpired) { reason = "expired"; return false; }

            // Ed25519 path: only attempted if both the verifier key and the
            // licence-borne signature are present. If the verifier key is set
            // but the licence has no Ed25519 sig, that is allowed (legacy
            // licence). If the licence has an Ed25519 sig but verification
            // fails, that *is* fatal — we do not silently downgrade.
            if (!string.IsNullOrEmpty(ed25519PublicKeyBase64) &&
                !string.IsNullOrEmpty(lic.SignatureEd25519))
            {
                byte[] pub, sig;
                try
                {
                    pub = Convert.FromBase64String(ed25519PublicKeyBase64);
                    sig = Convert.FromBase64String(lic.SignatureEd25519);
                }
                catch (FormatException) { reason = "bad ed25519 encoding"; return false; }

                var capturedHmac = lic.Signature;
                var capturedEd  = lic.SignatureEd25519;
                lic.Signature = null;
                lic.SignatureEd25519 = null;
                try
                {
                    var payload = JsonSerializer.Serialize(lic, JsonOpts);
                    var ok = Ed25519Crypto.Verify(Encoding.UTF8.GetBytes(payload), sig, pub);
                    if (!ok) { reason = "bad ed25519 signature"; return false; }
                    return true;
                }
                finally
                {
                    lic.Signature = capturedHmac;
                    lic.SignatureEd25519 = capturedEd;
                }
            }

            // Legacy HMAC fallback.
            if (string.IsNullOrEmpty(lic.Signature)) { reason = "missing signature"; return false; }
            var capturedSig = lic.Signature;
            var capturedEd2 = lic.SignatureEd25519;
            lic.Signature = null;
            lic.SignatureEd25519 = null;
            try
            {
                var payload = JsonSerializer.Serialize(lic, JsonOpts);
                var expected = Hmac(payload, hmacKey);
                if (!CryptographicOperations.FixedTimeEquals(
                        Encoding.ASCII.GetBytes(expected),
                        Encoding.ASCII.GetBytes(capturedSig)))
                {
                    reason = "bad signature";
                    return false;
                }
                return true;
            }
            finally
            {
                lic.Signature = capturedSig;
                lic.SignatureEd25519 = capturedEd2;
            }
        }

        public static License? Load(string path, string hmacKey, out string reason)
            => Load(path, hmacKey, ed25519PublicKeyBase64: null, out reason);

        public static License? Load(string path, string hmacKey, string? ed25519PublicKeyBase64, out string reason)
        {
            reason = "";
            try
            {
                var json = File.ReadAllText(path);
                var lic  = JsonSerializer.Deserialize<License>(json, JsonOpts);
                if (lic == null) { reason = "unparseable"; return null; }
                return Verify(lic, hmacKey, ed25519PublicKeyBase64, out reason) ? lic : null;
            }
            catch (Exception ex) { reason = ex.Message; return null; }
        }

        private static string Hmac(string payload, string key)
        {
            using var h = new HMACSHA256(Encoding.UTF8.GetBytes(key));
            var mac = h.ComputeHash(Encoding.UTF8.GetBytes(payload));
            return Convert.ToHexString(mac);
        }

        // Convenience: emit a free Community license without HMAC.
        public static License MakeCommunityTrial()
        {
            return Sign(new License
            {
                Customer = "community-trial",
                Sku      = "community",
                Issued   = DateTime.UtcNow,
                Expires  = DateTime.UtcNow.AddDays(30),
                Seats    = 1,
                Features = new List<string> { "scan", "report" },
            }, DefaultPublicKey);
        }
    }

    public static class FeatureGate
    {
        public static bool Allow(License? lic, string feature)
        {
            // Community gets the core detection pipeline; paid features are gated.
            if (lic == null)
                return feature is "scan" or "report";
            return lic.Has(feature) || lic.SkuEnum == LicenseSku.Enterprise;
        }
    }

    // ------------------------------------------------------------------
    // UpdateCheck — signed release manifest
    // ------------------------------------------------------------------
    public sealed class ReleaseManifest
    {
        [JsonPropertyName("version")]  public string Version  { get; set; } = "";
        [JsonPropertyName("released")] public DateTime Released { get; set; }
        [JsonPropertyName("sha256")]   public string Sha256   { get; set; } = "";
        [JsonPropertyName("url")]      public string Url      { get; set; } = "";
        [JsonPropertyName("notes")]    public string Notes    { get; set; } = "";
        [JsonPropertyName("signature")] public string? Signature { get; set; }
        // Section 13.6 — preferred Ed25519 detached signature (base64).
        [JsonPropertyName("signatureEd25519")] public string? SignatureEd25519 { get; set; }
    }

    public static class UpdateCheck
    {
        public static Task<ReleaseManifest?> CheckAsync(string manifestUrl, string hmacKey, HttpClient? http = null)
            => CheckAsync(manifestUrl, hmacKey, ed25519PublicKeyBase64: null, http);

        // Section 13.6 — verifier with optional Ed25519 vendor public key.
        // Same precedence rule as licence verification: if an Ed25519 key is
        // supplied AND the manifest carries a SignatureEd25519, that path is
        // tried (and failure is fatal). Otherwise we fall back to HMAC so old
        // manifests still validate.
        public static async Task<ReleaseManifest?> CheckAsync(string manifestUrl, string hmacKey, string? ed25519PublicKeyBase64, HttpClient? http = null)
        {
            http ??= SafeHttp.CreateClient(new SafeHttpOptions
            {
                Timeout          = TimeSpan.FromSeconds(8),
                MaxResponseBytes = 64 * 1024,
                UserAgent        = $"{ProductInfo.Name}/{ProductInfo.Version}",
            });
            try
            {
                var body = await http.GetStringAsync(manifestUrl).ConfigureAwait(false);
                var m = JsonSerializer.Deserialize<ReleaseManifest>(body, JsonOptionsRegistry.CamelCase);
                if (m == null) return null;

                if (!string.IsNullOrEmpty(ed25519PublicKeyBase64) &&
                    !string.IsNullOrEmpty(m.SignatureEd25519))
                {
                    byte[] pub, sig;
                    try
                    {
                        pub = Convert.FromBase64String(ed25519PublicKeyBase64);
                        sig = Convert.FromBase64String(m.SignatureEd25519);
                    }
                    catch (FormatException) { return null; }
                    var capturedSig = m.Signature;
                    var capturedEd  = m.SignatureEd25519;
                    m.Signature = null;
                    m.SignatureEd25519 = null;
                    var raw = JsonSerializer.Serialize(m, JsonOptionsRegistry.CamelCaseIndented);
                    var ok = Ed25519Crypto.Verify(Encoding.UTF8.GetBytes(raw), sig, pub);
                    m.Signature = capturedSig;
                    m.SignatureEd25519 = capturedEd;
                    return ok ? m : null;
                }

                if (string.IsNullOrEmpty(m.Signature)) return null;
                var captured = m.Signature;
                m.Signature = null;
                var raw2 = JsonSerializer.Serialize(m, JsonOptionsRegistry.CamelCaseIndented);
                using var h = new HMACSHA256(Encoding.UTF8.GetBytes(hmacKey));
                var expected = Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes(raw2)));
                m.Signature = captured;
                return CryptographicOperations.FixedTimeEquals(
                         Encoding.ASCII.GetBytes(expected),
                         Encoding.ASCII.GetBytes(captured))
                   ? m : null;
            }
            catch { return null; }
        }

        public static bool IsNewerThanCurrent(ReleaseManifest m) =>
            Version.TryParse(m.Version, out var remote) &&
            Version.TryParse(ProductInfo.Version, out var local) &&
            remote > local;
    }

    // ------------------------------------------------------------------
    // RestServer — POST /scan and GET /health
    // ------------------------------------------------------------------
    public sealed class RestServerOptions
    {
        public string   Prefix        { get; set; } = "http://127.0.0.1:8765/";
        public License? License       { get; set; }
        public string   LicenseKey    { get; set; } = LicenseVerifier.DefaultPublicKey;
        public long     MaxBodyBytes  { get; set; } = 128L * 1024 * 1024;
        public bool     RequirePro    { get; set; } = true;
    }

    public sealed class RestServer : IDisposable
    {
        private readonly RestServerOptions _opts;
        private readonly HttpListener _listener = new();
        private CancellationTokenSource? _cts;
        private Task? _loop;

        public RestServer(RestServerOptions opts)
        {
            _opts = opts;
            _listener.Prefixes.Add(opts.Prefix);
        }

        public void Start()
        {
            if (_opts.RequirePro && (_opts.License == null || _opts.License.SkuEnum == LicenseSku.Community))
                throw new InvalidOperationException("REST API requires a Pro or Enterprise license.");
            _cts = new CancellationTokenSource();
            _listener.Start();
            _loop = Task.Run(() => Loop(_cts.Token));
            AsiLogger.Info("rest server started", new Dictionary<string, object?>
            {
                ["prefix"] = _opts.Prefix,
                ["sku"]    = _opts.License?.Sku,
            });
        }

        public void Stop()
        {
            _cts?.Cancel();
            try { _listener.Stop(); } catch { }
            try { _loop?.Wait(TimeSpan.FromSeconds(2)); } catch { }
        }

        public void Dispose() => Stop();

        private async Task Loop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                HttpListenerContext? ctx = null;
                try { ctx = await _listener.GetContextAsync().ConfigureAwait(false); }
                catch { break; }
                _ = Task.Run(() => HandleAsync(ctx!, ct));
            }
        }

        private async Task HandleAsync(HttpListenerContext ctx, CancellationToken ct)
        {
            try
            {
                string path = ctx.Request.Url?.AbsolutePath ?? "";
                if (ctx.Request.HttpMethod == "GET" && path == "/health")
                {
                    await Json(ctx.Response, new { status = "ok", product = ProductInfo.Name, version = ProductInfo.Version, sku = _opts.License?.Sku }).ConfigureAwait(false);
                    return;
                }
                if (ctx.Request.HttpMethod == "POST" && path == "/scan")
                {
                    if (ctx.Request.ContentLength64 > _opts.MaxBodyBytes)
                    {
                        ctx.Response.StatusCode = 413;
                        await Json(ctx.Response, new { error = "payload too large" }).ConfigureAwait(false);
                        return;
                    }
                    var tmp = Path.Combine(Path.GetTempPath(), "ast-rest-" + Guid.NewGuid().ToString("N"));
                    using (var fs = File.Create(tmp))
                        await ctx.Request.InputStream.CopyToAsync(fs, ct).ConfigureAwait(false);
                    try
                    {
                        var result = Analyzer.Analyze(tmp, tmp);
                        var json = ReportWriter.ToJson(new[] { result });
                        ctx.Response.ContentType = "application/json";
                        var bytes = Encoding.UTF8.GetBytes(json);
                        ctx.Response.ContentLength64 = bytes.Length;
                        await ctx.Response.OutputStream.WriteAsync(bytes, 0, bytes.Length, ct).ConfigureAwait(false);
                    }
                    finally { try { File.Delete(tmp); } catch { } }
                    return;
                }
                ctx.Response.StatusCode = 404;
                await Json(ctx.Response, new { error = "not found" }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                try
                {
                    ctx.Response.StatusCode = 500;
                    await Json(ctx.Response, new { error = ex.Message }).ConfigureAwait(false);
                }
                catch { }
            }
            finally { try { ctx.Response.Close(); } catch { } }
        }

        private static async Task Json(HttpListenerResponse resp, object body)
        {
            resp.ContentType = "application/json";
            var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(body));
            resp.ContentLength64 = bytes.Length;
            await resp.OutputStream.WriteAsync(bytes, 0, bytes.Length).ConfigureAwait(false);
        }
    }
}
