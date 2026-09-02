// PR 9 — Section 9 (Intelligence providers):
//
//   9.1  IIntelProvider abstraction. A single interface that every
//        external-lookup backend implements (file-hash / URL / IP / domain).
//        Decouples the orchestration loop in Analyzer.EnrichWithCloudAsync
//        from the individual HTTP call shapes, and lets the test suite plug
//        in fakes without touching the network.
//   9.2  IntelCache. In-memory TTL cache (default 6h) with optional
//        disk-persistence to %APPDATA%\AntiStealer\intel-cache.json so a
//        re-scan of the same indicator doesn't burn the daily VirusTotal
//        quota. Cache keys are (provider-name, indicator-kind, value).
//   9.3  New providers. ThreatFox (abuse.ch, sha256 / url / ip / domain),
//        OTX (AlienVault, sha256 / url / ip / domain) and a LocalThreatIntel
//        provider that reads a newline-delimited file of indicators for
//        offline / air-gapped use.
//   9.4  Preflight. Before issuing a batch of lookups the orchestrator pings
//        a cheap health-check endpoint per provider (or validates the API
//        key with a HEAD request) and skips providers that fail — surfaces
//        wrong/expired keys instead of silently swallowing every 401.
//   9.5  Retry policy. Exponential backoff with jitter on 5xx / 429 /
//        transient HttpRequestException, capped by MaxAttempts.
//   9.6  Per-IOC enrichment. Every URL / IP / domain extracted from the
//        sample now gets its own lookup record (not just the file-hash
//        summary on AnalysisResult.CloudLookupResults), keyed by indicator
//        on AnalysisResult.IntelLookups so report writers can render a
//        per-indicator table.
//   9.7  Local TI feed. LocalThreatIntelProvider reads a plain-text file
//        (one indicator per line, "#" comments) and matches the sample's
//        indicators offline.
//   9.8  PCAP support. PcapReader parses a libpcap-format capture
//        (magic 0xa1b2c3d4 / 0xd4c3b2a1) and extracts unique IPv4
//        destinations and DNS A-query domains so the same intel
//        orchestrator can enrich network captures, not just executables.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace AntiStealerOneExe
{
    // -----------------------------------------------------------------
    // 9.1  Public surface — indicators, results, interface
    // -----------------------------------------------------------------

    public enum IndicatorKind
    {
        FileSha256 = 0,
        Url        = 1,
        Ipv4       = 2,
        Domain     = 3,
    }

    public sealed record IntelIndicator(IndicatorKind Kind, string Value)
    {
        public string CacheKey() => $"{(int)Kind}:{Value.ToLowerInvariant()}";
    }

    public enum IntelVerdict
    {
        Unknown    = 0,
        Clean      = 1,
        Suspicious = 2,
        Malicious  = 3,
    }

    public sealed class IntelLookupResult
    {
        public string Provider { get; set; } = "";
        public IndicatorKind Kind { get; set; }
        public string Indicator { get; set; } = "";
        public IntelVerdict Verdict { get; set; } = IntelVerdict.Unknown;
        public int Score { get; set; }              // 0..100 if available
        public string Summary { get; set; } = "";
        public DateTime FetchedAtUtc { get; set; }
        public TimeSpan Ttl { get; set; }           // 0 = no caching hint
        public string Error { get; set; } = "";    // empty on success

        public bool IsExpired(DateTime nowUtc) =>
            Ttl > TimeSpan.Zero && nowUtc - FetchedAtUtc > Ttl;
    }

    [Flags]
    public enum IntelCapability
    {
        None       = 0,
        FileSha256 = 1 << 0,
        Url        = 1 << 1,
        Ipv4       = 1 << 2,
        Domain     = 1 << 3,
    }

    public interface IIntelProvider
    {
        string Name { get; }
        IntelCapability Capabilities { get; }
        bool Supports(IndicatorKind kind);
        Task<bool> PreflightAsync(CancellationToken ct);
        Task<IntelLookupResult> LookupAsync(IntelIndicator indicator, CancellationToken ct);
    }

    // -----------------------------------------------------------------
    // 9.2  Cache
    // -----------------------------------------------------------------

    public sealed class IntelCache
    {
        private readonly ConcurrentDictionary<string, IntelLookupResult> _map = new();
        private readonly string? _persistPath;
        private readonly TimeSpan _defaultTtl;

        public IntelCache(string? persistPath = null, TimeSpan? defaultTtl = null)
        {
            _persistPath = persistPath;
            _defaultTtl = defaultTtl ?? TimeSpan.FromHours(6);
            TryLoad();
        }

        public int Count => _map.Count;

        public bool TryGet(string provider, IntelIndicator ind, out IntelLookupResult? hit)
        {
            hit = null;
            var k = $"{provider}|{ind.CacheKey()}";
            if (_map.TryGetValue(k, out var found) && !found.IsExpired(DateTime.UtcNow))
            {
                hit = found;
                return true;
            }
            return false;
        }

        public void Put(string provider, IntelIndicator ind, IntelLookupResult res)
        {
            if (res.Ttl == TimeSpan.Zero) res.Ttl = _defaultTtl;
            var k = $"{provider}|{ind.CacheKey()}";
            _map[k] = res;
        }

        public void Persist()
        {
            if (string.IsNullOrEmpty(_persistPath)) return;
            try
            {
                var dir = Path.GetDirectoryName(_persistPath);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                var json = JsonSerializer.Serialize(_map, JsonOptionsRegistry.CamelCaseIndented);
                File.WriteAllText(_persistPath, json);
            }
            catch { /* best-effort */ }
        }

        private void TryLoad()
        {
            if (string.IsNullOrEmpty(_persistPath) || !File.Exists(_persistPath)) return;
            try
            {
                var json = File.ReadAllText(_persistPath);
                var data = JsonSerializer.Deserialize<Dictionary<string, IntelLookupResult>>(json,
                              JsonOptionsRegistry.CamelCase);
                if (data == null) return;
                foreach (var kv in data)
                    if (!kv.Value.IsExpired(DateTime.UtcNow))
                        _map[kv.Key] = kv.Value;
            }
            catch { /* best-effort */ }
        }
    }

    // -----------------------------------------------------------------
    // 9.5  Retry policy
    // -----------------------------------------------------------------

    public sealed class IntelRetryPolicy
    {
        public int MaxAttempts { get; init; } = 3;
        public TimeSpan BaseDelay { get; init; } = TimeSpan.FromMilliseconds(250);
        public TimeSpan MaxDelay  { get; init; } = TimeSpan.FromSeconds(5);
        public Func<int, TimeSpan>? DelayOverride { get; init; }   // for unit tests
        private readonly Random _rng = new();

        public TimeSpan DelayFor(int attempt)
        {
            if (DelayOverride != null) return DelayOverride(attempt);
            // attempt is 1-based.
            var pow = Math.Min(8, attempt - 1);
            var raw = TimeSpan.FromMilliseconds(BaseDelay.TotalMilliseconds * Math.Pow(2, pow));
            if (raw > MaxDelay) raw = MaxDelay;
            // ±25% jitter
            double j = (_rng.NextDouble() * 0.5) + 0.75;
            return TimeSpan.FromMilliseconds(raw.TotalMilliseconds * j);
        }

        public async Task<T> ExecuteAsync<T>(Func<int, CancellationToken, Task<T>> op,
                                             Func<T, bool> shouldRetry,
                                             CancellationToken ct)
        {
            T last = default!;
            for (int attempt = 1; attempt <= MaxAttempts; attempt++)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    last = await op(attempt, ct);
                    if (!shouldRetry(last) || attempt == MaxAttempts) return last;
                }
                catch (OperationCanceledException) { throw; }
                catch
                {
                    if (attempt == MaxAttempts) throw;
                }
                try { await Task.Delay(DelayFor(attempt), ct); }
                catch (OperationCanceledException) { throw; }
            }
            return last;
        }
    }

    // -----------------------------------------------------------------
    // 9.7  Local threat-intel file provider
    // -----------------------------------------------------------------

    public sealed class LocalThreatIntelProvider : IIntelProvider
    {
        public string Name => "LocalTI";
        public IntelCapability Capabilities =>
            IntelCapability.FileSha256 | IntelCapability.Url | IntelCapability.Ipv4 | IntelCapability.Domain;

        private readonly HashSet<string> _sha = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _url = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _ip  = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _dom = new(StringComparer.OrdinalIgnoreCase);
        private readonly string _file;

        public LocalThreatIntelProvider(string file)
        {
            _file = file;
            LoadFromFile(file);
        }

        public bool Supports(IndicatorKind kind) =>
            (Capabilities & ToCap(kind)) != 0;

        public Task<bool> PreflightAsync(CancellationToken ct)
        {
            return Task.FromResult(File.Exists(_file));
        }

        public Task<IntelLookupResult> LookupAsync(IntelIndicator ind, CancellationToken ct)
        {
            var res = new IntelLookupResult
            {
                Provider     = Name,
                Kind         = ind.Kind,
                Indicator    = ind.Value,
                FetchedAtUtc = DateTime.UtcNow,
                Ttl          = TimeSpan.FromHours(1),
                Verdict      = IntelVerdict.Unknown,
            };

            bool hit = ind.Kind switch
            {
                IndicatorKind.FileSha256 => _sha.Contains(ind.Value),
                IndicatorKind.Url        => _url.Contains(ind.Value),
                IndicatorKind.Ipv4       => _ip .Contains(ind.Value),
                IndicatorKind.Domain     => _dom.Contains(ind.Value),
                _                        => false,
            };
            if (hit)
            {
                res.Verdict = IntelVerdict.Malicious;
                res.Score   = 100;
                res.Summary = "local-ti hit";
            }
            return Task.FromResult(res);
        }

        public int LoadedSha256 => _sha.Count;
        public int LoadedUrls   => _url.Count;
        public int LoadedIps    => _ip.Count;
        public int LoadedDomains => _dom.Count;

        private void LoadFromFile(string path)
        {
            if (!File.Exists(path)) return;
            try
            {
                foreach (var raw in File.ReadAllLines(path))
                {
                    var line = raw.Trim();
                    if (line.Length == 0 || line.StartsWith("#")) continue;
                    Classify(line);
                }
            }
            catch { /* best-effort */ }
        }

        private void Classify(string line)
        {
            // Strict sha256 = 64 hex chars
            if (line.Length == 64 && IsHex(line)) { _sha.Add(line); return; }
            // URL
            if (line.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                _url.Add(line);
                return;
            }
            // IPv4
            if (IsIpv4(line)) { _ip.Add(line); return; }
            // Domain — any other dotted token
            if (line.IndexOf('.') > 0 && !line.Any(char.IsWhiteSpace))
            {
                _dom.Add(line);
            }
        }

        private static bool IsHex(string s)
        {
            foreach (var c in s)
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                    return false;
            return true;
        }

        private static bool IsIpv4(string s)
        {
            var parts = s.Split('.');
            if (parts.Length != 4) return false;
            foreach (var p in parts)
                if (!byte.TryParse(p, NumberStyles.Integer, CultureInfo.InvariantCulture, out _))
                    return false;
            return true;
        }

        private static IntelCapability ToCap(IndicatorKind k) => k switch
        {
            IndicatorKind.FileSha256 => IntelCapability.FileSha256,
            IndicatorKind.Url        => IntelCapability.Url,
            IndicatorKind.Ipv4       => IntelCapability.Ipv4,
            IndicatorKind.Domain     => IntelCapability.Domain,
            _                        => IntelCapability.None,
        };
    }

    // -----------------------------------------------------------------
    // 9.3  ThreatFox / OTX — HTTP providers
    //
    // Both classes accept an HttpMessageHandler in the constructor so tests
    // can swap in a mock without touching the network.
    // -----------------------------------------------------------------

    public sealed class ThreatFoxProvider : IIntelProvider
    {
        public string Name => "ThreatFox";
        public IntelCapability Capabilities =>
            IntelCapability.FileSha256 | IntelCapability.Url | IntelCapability.Ipv4 | IntelCapability.Domain;

        private readonly HttpClient _http;
        private readonly string _endpoint;

        public ThreatFoxProvider(HttpMessageHandler? handler = null,
                                 string endpoint = "https://threatfox-api.abuse.ch/api/v1/")
        {
            _http = handler != null ? new HttpClient(handler, disposeHandler: false)
                                    : new HttpClient();
            _http.Timeout = TimeSpan.FromSeconds(10);
            _endpoint = endpoint;
        }

        public bool Supports(IndicatorKind kind) => true;
        public Task<bool> PreflightAsync(CancellationToken ct) => Task.FromResult(true);

        public async Task<IntelLookupResult> LookupAsync(IntelIndicator ind, CancellationToken ct)
        {
            var res = new IntelLookupResult
            {
                Provider     = Name,
                Kind         = ind.Kind,
                Indicator    = ind.Value,
                FetchedAtUtc = DateTime.UtcNow,
                Ttl          = TimeSpan.FromHours(2),
                Verdict      = IntelVerdict.Unknown,
            };
            try
            {
                var payload = JsonSerializer.Serialize(new { query = "search_ioc", search_term = ind.Value });
                using var req = new HttpRequestMessage(HttpMethod.Post, _endpoint)
                {
                    Content = new StringContent(payload, Encoding.UTF8, "application/json"),
                };
                using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
                if (!resp.IsSuccessStatusCode) { res.Error = $"HTTP {(int)resp.StatusCode}"; return res; }
                var text = await resp.Content.ReadAsStringAsync(ct);
                if (text.Contains("\"query_status\":\"ok\"", StringComparison.Ordinal))
                {
                    res.Verdict = IntelVerdict.Malicious;
                    res.Score   = 95;
                    res.Summary = ExtractSummary(text);
                }
                else if (text.Contains("\"query_status\":\"no_result\"", StringComparison.Ordinal))
                {
                    res.Verdict = IntelVerdict.Unknown;
                    res.Summary = "no_result";
                }
            }
            catch (Exception ex) { res.Error = ex.GetType().Name; }
            return res;
        }

        private static string ExtractSummary(string text)
        {
            // Pull a short "<malware> via <threat_type>" if present.
            string mw = ExtractJson(text, "\"malware\":");
            string tt = ExtractJson(text, "\"threat_type\":");
            if (mw.Length == 0 && tt.Length == 0) return "match";
            return $"{mw} {tt}".Trim();
        }

        internal static string ExtractJson(string text, string keyWithQuote)
        {
            int i = text.IndexOf(keyWithQuote, StringComparison.Ordinal);
            if (i < 0) return "";
            i += keyWithQuote.Length;
            while (i < text.Length && (text[i] == ' ' || text[i] == '\t')) i++;
            if (i >= text.Length || text[i] != '"') return "";
            i++;
            int end = text.IndexOf('"', i);
            return end > i ? text.Substring(i, end - i) : "";
        }
    }

    public sealed class OtxProvider : IIntelProvider
    {
        public string Name => "OTX";
        public IntelCapability Capabilities =>
            IntelCapability.FileSha256 | IntelCapability.Url | IntelCapability.Ipv4 | IntelCapability.Domain;

        private readonly HttpClient _http;
        private readonly string _apiKey;
        private readonly string _base;

        public OtxProvider(string apiKey,
                           HttpMessageHandler? handler = null,
                           string apiBase = "https://otx.alienvault.com/api/v1/")
        {
            _http = handler != null ? new HttpClient(handler, disposeHandler: false)
                                    : new HttpClient();
            _http.Timeout = TimeSpan.FromSeconds(10);
            _apiKey = apiKey ?? "";
            _base = apiBase.TrimEnd('/') + "/";
        }

        public bool Supports(IndicatorKind kind) => true;

        public async Task<bool> PreflightAsync(CancellationToken ct)
        {
            if (string.IsNullOrEmpty(_apiKey)) return false;
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, _base + "user/me");
                req.Headers.TryAddWithoutValidation("X-OTX-API-KEY", _apiKey);
                using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
                return resp.IsSuccessStatusCode;
            }
            catch { return false; }
        }

        public async Task<IntelLookupResult> LookupAsync(IntelIndicator ind, CancellationToken ct)
        {
            var res = new IntelLookupResult
            {
                Provider     = Name,
                Kind         = ind.Kind,
                Indicator    = ind.Value,
                FetchedAtUtc = DateTime.UtcNow,
                Ttl          = TimeSpan.FromHours(6),
                Verdict      = IntelVerdict.Unknown,
            };
            if (string.IsNullOrEmpty(_apiKey)) { res.Error = "no-api-key"; return res; }
            try
            {
                var path = ind.Kind switch
                {
                    IndicatorKind.FileSha256 => $"indicators/file/{ind.Value}/general",
                    IndicatorKind.Url        => $"indicators/url/{Uri.EscapeDataString(ind.Value)}/general",
                    IndicatorKind.Ipv4       => $"indicators/IPv4/{ind.Value}/general",
                    IndicatorKind.Domain     => $"indicators/domain/{ind.Value}/general",
                    _ => "",
                };
                if (path.Length == 0) { res.Error = "unsupported-kind"; return res; }
                using var req = new HttpRequestMessage(HttpMethod.Get, _base + path);
                req.Headers.TryAddWithoutValidation("X-OTX-API-KEY", _apiKey);
                using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
                if (!resp.IsSuccessStatusCode) { res.Error = $"HTTP {(int)resp.StatusCode}"; return res; }
                var text = await resp.Content.ReadAsStringAsync(ct);
                int pulses = ExtractInt(text, "\"pulse_count\":");
                if (pulses > 0)
                {
                    res.Verdict = pulses >= 3 ? IntelVerdict.Malicious : IntelVerdict.Suspicious;
                    res.Score = Math.Min(100, pulses * 10);
                    res.Summary = $"pulses={pulses}";
                }
                else res.Summary = "no_pulses";
            }
            catch (Exception ex) { res.Error = ex.GetType().Name; }
            return res;
        }

        private static int ExtractInt(string text, string keyWithQuote)
        {
            int i = text.IndexOf(keyWithQuote, StringComparison.Ordinal);
            if (i < 0) return 0;
            i += keyWithQuote.Length;
            while (i < text.Length && (text[i] == ' ' || text[i] == '\t')) i++;
            int start = i;
            while (i < text.Length && (char.IsDigit(text[i]) || text[i] == '-')) i++;
            if (i == start) return 0;
            int.TryParse(text.AsSpan(start, i - start), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v);
            return v;
        }
    }

    // -----------------------------------------------------------------
    // 9.4 / 9.5 / 9.6  Orchestrator
    // -----------------------------------------------------------------

    public sealed class IntelOrchestrator
    {
        private readonly List<IIntelProvider> _providers;
        private readonly IntelCache _cache;
        private readonly IntelRetryPolicy _retry;

        public IntelOrchestrator(IEnumerable<IIntelProvider> providers,
                                 IntelCache? cache = null,
                                 IntelRetryPolicy? retry = null)
        {
            _providers = providers.ToList();
            _cache     = cache ?? new IntelCache();
            _retry     = retry ?? new IntelRetryPolicy();
        }

        public IReadOnlyList<IIntelProvider> Providers => _providers;
        public IntelCache Cache => _cache;

        /// <summary>
        /// Run preflight on every provider in parallel; returns the list that
        /// answered ok. Providers that fail preflight are silently dropped for
        /// this invocation (and counted in the returned dictionary).
        /// </summary>
        public async Task<Dictionary<string, bool>> RunPreflightAsync(CancellationToken ct)
        {
            var tasks = _providers.Select(async p =>
            {
                bool ok;
                try { ok = await p.PreflightAsync(ct); }
                catch { ok = false; }
                return (p.Name, ok);
            }).ToList();
            var pairs = await Task.WhenAll(tasks);
            return pairs.ToDictionary(t => t.Name, t => t.ok);
        }

        public async Task<List<IntelLookupResult>> LookupAsync(IEnumerable<IntelIndicator> indicators,
                                                               CancellationToken ct)
        {
            var preflight = await RunPreflightAsync(ct);
            var live = _providers.Where(p => preflight.TryGetValue(p.Name, out var v) && v).ToList();

            var results = new List<IntelLookupResult>();
            // Dedupe indicators by (Kind, lower-Value)
            var seen = new HashSet<string>();
            foreach (var ind in indicators)
            {
                if (!seen.Add(ind.CacheKey())) continue;
                foreach (var p in live)
                {
                    if (!p.Supports(ind.Kind)) continue;
                    if (_cache.TryGet(p.Name, ind, out var hit) && hit != null)
                    {
                        results.Add(hit);
                        continue;
                    }
                    try
                    {
                        var r = await _retry.ExecuteAsync(
                            (_, c) => p.LookupAsync(ind, c),
                            r => !string.IsNullOrEmpty(r.Error),
                            ct);
                        if (string.IsNullOrEmpty(r.Error)) _cache.Put(p.Name, ind, r);
                        results.Add(r);
                    }
                    catch (Exception ex)
                    {
                        results.Add(new IntelLookupResult
                        {
                            Provider     = p.Name,
                            Kind         = ind.Kind,
                            Indicator    = ind.Value,
                            FetchedAtUtc = DateTime.UtcNow,
                            Verdict      = IntelVerdict.Unknown,
                            Error        = ex.GetType().Name,
                        });
                    }
                }
            }
            return results;
        }
    }

    // -----------------------------------------------------------------
    // 9.8  PCAP reader — minimal libpcap parser
    // -----------------------------------------------------------------

    /// <summary>
    /// Reads a libpcap-format file (magic 0xa1b2c3d4 / 0xd4c3b2a1) and pulls
    /// out unique IPv4 destination addresses and DNS A-query domain names.
    /// Designed for offline triage of network captures alongside a sample,
    /// not as a full protocol analyser — we deliberately ignore IPv6, UDP/TCP
    /// payload parsing beyond DNS port 53 questions, and link-type variants
    /// other than LINKTYPE_ETHERNET (1) and LINKTYPE_RAW (101 / 12).
    /// </summary>
    public static class PcapReader
    {
        public sealed class PcapIndicators
        {
            public HashSet<string> Ipv4 { get; } = new();
            public HashSet<string> Domains { get; } = new();
            public int PacketCount { get; set; }
            public int DroppedPacketCount { get; set; }
        }

        public static PcapIndicators Read(string path)
        {
            using var fs = File.OpenRead(path);
            return Read(fs);
        }

        public static PcapIndicators Read(Stream stream)
        {
            var ind = new PcapIndicators();
            using var br = new BinaryReader(stream);
            if (stream.Length < 24) return ind;

            uint magic = br.ReadUInt32();
            bool swap;
            switch (magic)
            {
                case 0xa1b2c3d4u: swap = false; break;
                case 0xd4c3b2a1u: swap = true;  break;
                default: return ind;            // not a libpcap file
            }
            ushort major = ReadU16(br, swap);
            ushort minor = ReadU16(br, swap);
            _ = ReadU32(br, swap); // thiszone
            _ = ReadU32(br, swap); // sigfigs
            _ = ReadU32(br, swap); // snaplen
            uint linkType = ReadU32(br, swap);
            // we accept Ethernet (1) and raw IP (101/12); for anything else we
            // still attempt to peek; bogus link types will just yield no IOCs.

            byte[] hdr = new byte[16];
            while (stream.Position < stream.Length)
            {
                int read = stream.Read(hdr, 0, 16);
                if (read < 16) break;
                uint inclLen = BitConverter.ToUInt32(hdr, 8);
                if (swap) inclLen = SwapU32(inclLen);
                if (inclLen == 0 || inclLen > 65_535) { ind.DroppedPacketCount++; break; }
                byte[] pkt = br.ReadBytes((int)inclLen);
                if (pkt.Length < inclLen) break;
                ind.PacketCount++;
                ParsePacket(pkt, linkType, ind);
            }
            return ind;
        }

        private static void ParsePacket(byte[] pkt, uint linkType, PcapIndicators ind)
        {
            int ipOff = linkType switch
            {
                1   => 14,            // Ethernet
                101 => 0,             // LINKTYPE_RAW
                12  => 0,             // also raw on some BSDs
                _   => 14,
            };
            if (pkt.Length < ipOff + 20) return;
            // version
            byte v = pkt[ipOff];
            int version = v >> 4;
            int ihl = (v & 0x0F) * 4;
            if (version != 4 || ihl < 20 || pkt.Length < ipOff + ihl + 8) return;
            // dst at offset 16..19 inside the IP header
            string dst = $"{pkt[ipOff + 16]}.{pkt[ipOff + 17]}.{pkt[ipOff + 18]}.{pkt[ipOff + 19]}";
            ind.Ipv4.Add(dst);

            // DNS A questions: UDP/53
            byte proto = pkt[ipOff + 9];
            if (proto == 17) // UDP
            {
                int udpOff = ipOff + ihl;
                if (pkt.Length < udpOff + 8) return;
                int dport = (pkt[udpOff + 2] << 8) | pkt[udpOff + 3];
                if (dport == 53)
                {
                    int dnsOff = udpOff + 8;
                    if (pkt.Length < dnsOff + 12) return;
                    ushort flags = (ushort)((pkt[dnsOff + 2] << 8) | pkt[dnsOff + 3]);
                    bool isQuery = (flags & 0x8000) == 0;
                    ushort qdCount = (ushort)((pkt[dnsOff + 4] << 8) | pkt[dnsOff + 5]);
                    if (!isQuery || qdCount == 0) return;
                    int p = dnsOff + 12;
                    var sb = new StringBuilder();
                    while (p < pkt.Length)
                    {
                        byte len = pkt[p];
                        if (len == 0) break;
                        if ((len & 0xC0) != 0) return;        // pointers; skip
                        p++;
                        if (p + len > pkt.Length) return;
                        if (sb.Length > 0) sb.Append('.');
                        sb.Append(Encoding.ASCII.GetString(pkt, p, len));
                        p += len;
                    }
                    var name = sb.ToString();
                    if (name.IndexOf('.') > 0 && name.Length <= 253)
                        ind.Domains.Add(name);
                }
            }
        }

        private static ushort ReadU16(BinaryReader br, bool swap)
        {
            ushort v = br.ReadUInt16();
            return swap ? (ushort)((v >> 8) | (v << 8)) : v;
        }
        private static uint ReadU32(BinaryReader br, bool swap)
        {
            uint v = br.ReadUInt32();
            return swap ? SwapU32(v) : v;
        }
        private static uint SwapU32(uint v) =>
            ((v & 0x000000FFu) << 24) |
            ((v & 0x0000FF00u) << 8)  |
            ((v & 0x00FF0000u) >> 8)  |
            ((v & 0xFF000000u) >> 24);
    }

    // -----------------------------------------------------------------
    // AnalysisResult extensions — per-indicator lookups + PCAP IOCs
    // -----------------------------------------------------------------

    public sealed partial class AnalysisResult
    {
        // Key = "<provider>|<kind>:<value>"
        public Dictionary<string, IntelLookupResult> IntelLookups { get; set; } = new();
        public List<string> PcapDomainHits { get; set; } = new();
        public List<string> PcapIpHits { get; set; } = new();
    }
}
