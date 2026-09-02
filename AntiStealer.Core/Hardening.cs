using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text.Json;

// GG1–GG10: security hardening building blocks.
//
// This module is dependency-free. It provides:
//
//   GG2  SafeExtract.Zip(stream, destDir, opts) — quota-bounded archive
//        extraction with depth limit, per-entry size cap, overall cap,
//        compression-ratio sanity check and path-traversal rejection.
//
//   GG3  SafeHttp.CreateClient(opts) — HttpClient with strict timeout,
//        TLS 1.2/1.3 only, per-response byte cap, redirect limit,
//        user-agent pinning and optional certificate pinning via SHA-256.
//
//   GG5  AsiLogger.Log(level, message, props) — lightweight structured
//        logger that emits NDJSON lines to a rolling file under
//        %LOCALAPPDATA%\AntiStealer\logs\YYYY-MM-DD.log and (optionally)
//        mirrors to stderr.
//
//   GG6  CrashReporter.Install() — AppDomain.UnhandledException + TaskScheduler
//        hooks that write a crash JSON under %LOCALAPPDATA%\AntiStealer\crash\
//        including a one-line summary, stack trace, offending SHA-256 if
//        known, and environment metadata.
//
//   GG9  EncryptedQuarantine.Quarantine(path, sha256) — XOR-encrypt the
//        file under a fresh random key and store it under
//        %LOCALAPPDATA%\AntiStealer\quarantine\<sha>.q alongside a .keyjson
//        metadata sidecar. The payload cannot execute even if re-opened.

namespace AntiStealerOneExe
{
    // ------------------------------------------------------------------
    // GG2 — SafeExtract (zip)
    // ------------------------------------------------------------------
    public sealed class SafeExtractOptions
    {
        public long   MaxTotalBytes     { get; set; } = 256L * 1024 * 1024;
        public long   MaxEntryBytes     { get; set; } = 64L * 1024 * 1024;
        public int    MaxDepth          { get; set; } = 4;
        public int    MaxEntries        { get; set; } = 4096;
        public double MaxExpansionRatio { get; set; } = 100.0;
        public bool   AllowSymlinks     { get; set; } = false;
    }

    public static class SafeExtract
    {
        public sealed class ExtractResult
        {
            public int  EntriesExtracted { get; set; }
            public long TotalBytes       { get; set; }
            public List<string> Rejected { get; set; } = new();
        }

        public static ExtractResult Zip(Stream zipStream, string destDir, SafeExtractOptions? opts = null)
        {
            opts ??= new SafeExtractOptions();
            Directory.CreateDirectory(destDir);

            // GG2 (v2) — path-traversal hardening.
            //
            // The previous implementation used a `root` without a
            // trailing separator and a `StartsWith(root)` check. That
            // accepts `root = C:\tmp\a`, `full = C:\tmp\a_evil\x` as a
            // valid path because the comparison is a pure prefix
            // match. Fix: normalise `root` to always end in a directory
            // separator, then the prefix check is unambiguous. Also
            // refuse a target that resolves exactly to `root` (the
            // archive shouldn't be able to overwrite the parent
            // directory itself), and reject NUL bytes / absolute paths
            // in entry names since those bypass `Combine` semantics on
            // some platforms.
            string root = Path.GetFullPath(destDir)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                + Path.DirectorySeparatorChar;
            var result = new ExtractResult();

            using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read, leaveOpen: true);
            long total = 0;
            int  count = 0;
            foreach (var entry in archive.Entries)
            {
                if (count >= opts.MaxEntries)    { result.Rejected.Add($"{entry.FullName}: entry-cap"); break; }
                count++;

                var entryName = entry.FullName ?? string.Empty;

                // Disallow obviously hostile entry names regardless of
                // platform: absolute paths, drive letters, NUL bytes.
                if (entryName.Length == 0 ||
                    entryName.IndexOf('\0') >= 0 ||
                    Path.IsPathRooted(entryName) ||
                    (entryName.Length >= 2 && entryName[1] == ':'))
                {
                    result.Rejected.Add($"{entryName}: absolute/rooted-name");
                    continue;
                }

                // Path-traversal: the normalized target must live STRICTLY
                // inside destDir (not at destDir itself, not in a sibling
                // whose name happens to share a prefix).
                string combined;
                try { combined = Path.GetFullPath(Path.Combine(root, entryName)); }
                catch
                {
                    result.Rejected.Add($"{entryName}: invalid-path");
                    continue;
                }

                var full = combined;
                bool inside = full.StartsWith(root, StringComparison.OrdinalIgnoreCase) &&
                              full.Length > root.Length;
                if (!inside)
                {
                    result.Rejected.Add($"{entryName}: path-traversal");
                    continue;
                }

                // Symlink / reparse-point entries — refuse unless the
                // caller explicitly opted in (default: off). ZIP stores
                // symlink mode in the Unix external attributes upper
                // bits; ZipArchiveEntry doesn't expose them directly so
                // we conservatively reject anything that looks like a
                // symlink target (empty file with a path payload) when
                // the option is disabled.
                if (!opts.AllowSymlinks)
                {
                    // Best-effort: a zero-length entry whose data is a
                    // single line of text resembling a path is treated
                    // as a symlink. This is heuristic but errs on the
                    // side of safety.
                    if (entry.Length == 0 && entry.CompressedLength > 0 && entry.CompressedLength < 4096)
                    {
                        // Probe content to see if it's a path.
                        try
                        {
                            using var probe = entry.Open();
                            var buf = new byte[(int)entry.CompressedLength];
                            int read = probe.Read(buf, 0, buf.Length);
                            var text = System.Text.Encoding.UTF8.GetString(buf, 0, read);
                            if (text.Length > 0 && (text.IndexOf('/') >= 0 || text.IndexOf('\\') >= 0) &&
                                text.IndexOf('\0') < 0 && !text.Contains("\n"))
                            {
                                result.Rejected.Add($"{entryName}: symlink-disallowed");
                                continue;
                            }
                        }
                        catch { /* fall through and treat as regular */ }
                    }
                }

                // Depth cap.
                int depth = entryName.Count(c => c == '/' || c == '\\');
                if (depth > opts.MaxDepth)
                {
                    result.Rejected.Add($"{entryName}: depth>{opts.MaxDepth}");
                    continue;
                }

                if (entryName.EndsWith("/") || entryName.EndsWith("\\"))
                {
                    Directory.CreateDirectory(full);
                    continue;
                }

                // Per-entry size.
                if (entry.Length > opts.MaxEntryBytes)
                {
                    result.Rejected.Add($"{entryName}: entry>{opts.MaxEntryBytes}");
                    continue;
                }

                // Compression-ratio sanity (zip-bomb shield).
                if (entry.CompressedLength > 0 && entry.Length / (double)entry.CompressedLength > opts.MaxExpansionRatio)
                {
                    result.Rejected.Add($"{entryName}: ratio>{opts.MaxExpansionRatio:F0}x");
                    continue;
                }

                total += entry.Length;
                if (total > opts.MaxTotalBytes)
                {
                    result.Rejected.Add($"{entryName}: total>{opts.MaxTotalBytes}");
                    break;
                }

                Directory.CreateDirectory(Path.GetDirectoryName(full)!);
                using var es = entry.Open();
                using var fs = new FileStream(full, FileMode.Create, FileAccess.Write, FileShare.None);
                es.CopyTo(fs);
                result.EntriesExtracted++;
            }
            result.TotalBytes = total;
            return result;
        }
    }

    // ------------------------------------------------------------------
    // GG3 — SafeHttp
    // ------------------------------------------------------------------
    public sealed class SafeHttpOptions
    {
        public TimeSpan Timeout         { get; set; } = TimeSpan.FromSeconds(8);
        public long     MaxResponseBytes { get; set; } = 4L * 1024 * 1024;
        public string   UserAgent       { get; set; } = "AntiStealer/1.0";
        public int      MaxRedirects    { get; set; } = 2;
        public string?  ExpectedServerCertSha256 { get; set; }  // optional pinning
    }

    public static class SafeHttp
    {
        public static HttpClient CreateClient(SafeHttpOptions? opts = null)
        {
            opts ??= new SafeHttpOptions();
            var handler = new SocketsHttpHandler
            {
                AllowAutoRedirect       = opts.MaxRedirects > 0,
                MaxAutomaticRedirections = Math.Max(1, opts.MaxRedirects),
                AutomaticDecompression  = DecompressionMethods.All,
                ConnectTimeout          = opts.Timeout,
                SslOptions              = new SslClientAuthenticationOptions
                {
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12
                                        | System.Security.Authentication.SslProtocols.Tls13,
                    RemoteCertificateValidationCallback = (sender, cert, chain, errs) =>
                    {
                        if (cert == null) return false;
                        if (errs != SslPolicyErrors.None) return false;
                        if (string.IsNullOrEmpty(opts.ExpectedServerCertSha256)) return true;
                        var fp = HexUtil.ToLowerHex(SHA256.HashData(cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert)));
                        return string.Equals(fp, opts.ExpectedServerCertSha256, StringComparison.OrdinalIgnoreCase);
                    },
                },
            };
            var client = new HttpClient(handler) { Timeout = opts.Timeout };
            client.DefaultRequestHeaders.UserAgent.ParseAdd(opts.UserAgent);
            client.MaxResponseContentBufferSize = opts.MaxResponseBytes;
            return client;
        }
    }

    // ------------------------------------------------------------------
    // GG5 — AsiLogger (structured, NDJSON rolling file)
    // ------------------------------------------------------------------
    public enum AsiLogLevel { Trace, Debug, Info, Warn, Error }

    public static class AsiLogger
    {
        public static string LogDir { get; set; } =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                         "AntiStealer", "logs");
        public static bool MirrorToStderr { get; set; } = false;
        private static readonly object Lock = new();

        public static void Log(AsiLogLevel level, string message, IReadOnlyDictionary<string, object?>? props = null)
        {
            var entry = new Dictionary<string, object?>
            {
                ["ts"]      = DateTime.UtcNow.ToString("o"),
                ["level"]   = level.ToString().ToLowerInvariant(),
                ["msg"]     = message,
                ["pid"]     = Environment.ProcessId,
                ["thread"]  = Environment.CurrentManagedThreadId,
            };
            if (props != null)
                foreach (var kv in props) entry[kv.Key] = kv.Value;

            var json = JsonSerializer.Serialize(entry);
            try
            {
                Directory.CreateDirectory(LogDir);
                var path = Path.Combine(LogDir, DateTime.UtcNow.ToString("yyyy-MM-dd") + ".log");
                lock (Lock) File.AppendAllText(path, json + Environment.NewLine);
            }
            catch { /* logging must never throw */ }

            if (MirrorToStderr) Console.Error.WriteLine(json);
        }

        public static void Info (string msg, IReadOnlyDictionary<string, object?>? p = null) => Log(AsiLogLevel.Info,  msg, p);
        public static void Warn (string msg, IReadOnlyDictionary<string, object?>? p = null) => Log(AsiLogLevel.Warn,  msg, p);
        public static void Error(string msg, IReadOnlyDictionary<string, object?>? p = null) => Log(AsiLogLevel.Error, msg, p);
    }

    // ------------------------------------------------------------------
    // GG6 — Crash reporter
    // ------------------------------------------------------------------
    public static class CrashReporter
    {
        public static string CrashDir { get; set; } =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                         "AntiStealer", "crash");

        // Optional: identifies the sample currently being analyzed so the
        // crash report carries its SHA-256.
        public static string? CurrentSampleSha256 { get; set; }
        public static string? CurrentSamplePath   { get; set; }

        private static bool _installed;

        public static void Install()
        {
            if (_installed) return;
            _installed = true;
            AppDomain.CurrentDomain.UnhandledException += (s, e) =>
                Write(e.ExceptionObject as Exception, "AppDomain.UnhandledException");
            System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (s, e) =>
            {
                Write(e.Exception, "TaskScheduler.UnobservedTaskException");
                e.SetObserved();
            };
        }

        public static void Write(Exception? ex, string source)
        {
            try
            {
                Directory.CreateDirectory(CrashDir);
                var blob = new
                {
                    ts             = DateTime.UtcNow.ToString("o"),
                    source,
                    message        = ex?.Message,
                    stack          = ex?.ToString(),
                    inner          = ex?.InnerException?.ToString(),
                    sample_sha256  = CurrentSampleSha256,
                    sample_path    = CurrentSamplePath,
                    os             = Environment.OSVersion.ToString(),
                    clr            = Environment.Version.ToString(),
                    machine        = Environment.MachineName,
                    process        = System.Diagnostics.Process.GetCurrentProcess().ProcessName,
                    cwd            = Environment.CurrentDirectory,
                };
                string fname = $"crash-{DateTime.UtcNow:yyyyMMdd-HHmmss-fff}.json";
                File.WriteAllText(Path.Combine(CrashDir, fname),
                                  JsonSerializer.Serialize(blob, JsonOptionsRegistry.Indented));
            }
            catch { /* never throw from the crash reporter */ }
        }
    }

    // ------------------------------------------------------------------
    // GG9 — EncryptedQuarantine
    //
    // Section 13.1: replace the legacy XOR-key obfuscation with AES-GCM
    // authenticated encryption. AES-GCM gives confidentiality *and*
    // integrity (any bit flip in the ciphertext is rejected on Restore),
    // which the XOR scheme could not. Existing on-disk quarantine files
    // (those whose .keyjson does not carry a NonceB64) are still readable
    // via the legacy code path so customers don't lose access to historic
    // captures after upgrade.
    //
    // On-disk layout for v2:
    //   <sha>.q       = ciphertext (raw bytes, no header)
    //   <sha>.keyjson = JSON QuarantineRecord with Version=2, KeyB64,
    //                   NonceB64, TagB64, OriginalPath, When, Length, ...
    // ------------------------------------------------------------------
    public static class EncryptedQuarantine
    {
        public static string QuarantineDir { get; set; } =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                         "AntiStealer", "quarantine");

        // AES-GCM standard nonce length. NIST SP 800-38D recommends 96 bits.
        private const int NonceSizeBytes = 12;
        // AES-GCM tag length. We use the maximum (128 bits) for strongest
        // forgery resistance.
        private const int TagSizeBytes = 16;

        public sealed class QuarantineRecord
        {
            // Schema discriminator: 1 = legacy XOR (KeyHex-only),
            // 2 = AES-GCM (KeyB64 + NonceB64 + TagB64).
            public int    Version      { get; set; } = 2;
            public string Sha256       { get; set; } = "";

            // Section 13.1 — legacy XOR key (hex). Absent on v2 records but
            // retained on the type so old .keyjson files still deserialise.
            public string KeyHex       { get; set; } = "";

            // AES-GCM key, nonce and authentication tag (base64).
            public string KeyB64       { get; set; } = "";
            public string NonceB64     { get; set; } = "";
            public string TagB64       { get; set; } = "";

            public string OriginalPath { get; set; } = "";
            public DateTime When       { get; set; }
            public long   Length       { get; set; }
            public string StoredPath   { get; set; } = "";
        }

        public static QuarantineRecord Quarantine(string path, string sha256)
        {
            Directory.CreateDirectory(QuarantineDir);

            // 32-byte (AES-256) key, 12-byte nonce, both freshly random.
            byte[] key   = RandomNumberGenerator.GetBytes(32);
            byte[] nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);

            var plain      = File.ReadAllBytes(path);
            var ciphertext = new byte[plain.Length];
            var tag        = new byte[TagSizeBytes];

            // AesGcm requires a fixed-tag-size constructor on .NET 8+ to avoid
            // the obsoletion warning about the default tag size.
            using (var gcm = new AesGcm(key, TagSizeBytes))
            {
                gcm.Encrypt(nonce, plain, ciphertext, tag);
            }

            string stored = Path.Combine(QuarantineDir, sha256 + ".q");
            string meta   = Path.Combine(QuarantineDir, sha256 + ".keyjson");
            // Section 13.3 — defence-in-depth: even though sha256 is
            // produced by us internally and Path.Combine already rejects
            // most traversal, validate that the resolved path lands under
            // QuarantineDir. A caller passing a maliciously-crafted sha
            // (e.g. with NUL or alt-separators) would otherwise be able
            // to drop a file outside the quarantine root.
            DropValidator.EnsureUnderRoot(stored, QuarantineDir, "EncryptedQuarantine.Quarantine");
            DropValidator.EnsureUnderRoot(meta,   QuarantineDir, "EncryptedQuarantine.Quarantine");
            File.WriteAllBytes(stored, ciphertext);

            var rec = new QuarantineRecord
            {
                Version      = 2,
                Sha256       = sha256,
                KeyB64       = Convert.ToBase64String(key),
                NonceB64     = Convert.ToBase64String(nonce),
                TagB64       = Convert.ToBase64String(tag),
                OriginalPath = path,
                When         = DateTime.UtcNow,
                Length       = plain.Length,
                StoredPath   = stored,
            };
            File.WriteAllText(meta, JsonSerializer.Serialize(rec, JsonOptionsRegistry.Indented));
            return rec;
        }

        public static byte[] Restore(string sha256)
        {
            string stored = Path.Combine(QuarantineDir, sha256 + ".q");
            string meta   = Path.Combine(QuarantineDir, sha256 + ".keyjson");
            var rec  = JsonSerializer.Deserialize<QuarantineRecord>(File.ReadAllText(meta))
                        ?? throw new InvalidDataException("quarantine key missing");
            byte[] data = File.ReadAllBytes(stored);

            // Section 13.1 — v2 (AES-GCM) record: must have all three blobs.
            // We treat absence of any of them as "fall back to v1".
            bool hasGcmBlobs = !string.IsNullOrEmpty(rec.NonceB64)
                            && !string.IsNullOrEmpty(rec.TagB64)
                            && !string.IsNullOrEmpty(rec.KeyB64);
            if (rec.Version >= 2 || hasGcmBlobs)
            {
                byte[] key   = Convert.FromBase64String(rec.KeyB64);
                byte[] nonce = Convert.FromBase64String(rec.NonceB64);
                byte[] tag   = Convert.FromBase64String(rec.TagB64);
                var plain    = new byte[data.Length];
                using var gcm = new AesGcm(key, TagSizeBytes);
                // AuthenticationTagMismatchException bubbles up if the
                // ciphertext or tag was tampered with — desired behaviour.
                gcm.Decrypt(nonce, data, tag, plain);
                return plain;
            }

            // Legacy v1 (XOR). Only reachable for .keyjson files written
            // before the AES-GCM migration.
            byte[] xorKey = Convert.FromHexString(rec.KeyHex);
            for (int i = 0; i < data.Length; i++) data[i] ^= xorKey[i % xorKey.Length];
            return data;
        }
    }
}
