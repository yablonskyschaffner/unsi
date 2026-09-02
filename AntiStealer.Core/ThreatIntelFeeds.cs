// PR 15 — Stage C20:  Auto threat-intel feed ingestion
// ─────────────────────────────────────────────────────────────────
// Pulls remote / local threat-intel feeds on a schedule and merges
// the resulting indicators (sha256 / url / ipv4 / domain / imphash /
// tlsh) into a single offline pool.  The Analyzer consults this pool
// at the per-result enrichment stage (`AnalyzeFeedMatches`) and
// records hits in `AnalysisResult.FeedHits` so a downstream Score()
// bump can fire without a network round-trip.
//
// Design notes:
//
//   * Configuration is read from `<exe-dir>/intel/feeds.json`:
//
//       [
//         { "name": "urlhaus",       "format": "urlhaus_csv",
//           "source": "https://urlhaus.abuse.ch/downloads/csv_recent/",
//           "ttl_hours": 6 },
//         { "name": "threatfox",     "format": "threatfox_csv",
//           "source": "https://threatfox.abuse.ch/export/csv/recent/",
//           "ttl_hours": 6 },
//         { "name": "malwarebazaar", "format": "mb_csv",
//           "source": "https://bazaar.abuse.ch/export/csv/recent/",
//           "ttl_hours": 12 },
//         { "name": "cisa-stix",     "format": "stix",
//           "source": "https://www.cisa.gov/.../advisory.json",
//           "ttl_hours": 24 },
//         { "name": "local-denylist","format": "plain",
//           "source": "file:///etc/antistealer/denylist.txt",
//           "ttl_hours": 1 }
//       ]
//
//     For air-gapped deployments use `file:///` URLs that point at a
//     locally-staged copy of each feed.
//
//   * Each refresh writes the parsed indicators to
//     `<intel-dir>/cache/<feed>.idx` (one `kind:value` per line) and
//     a sibling `<feed>.meta` containing the last fetch timestamp.
//     The next `RefreshAsync()` skips feeds whose `meta` is younger
//     than `ttl_hours`.
//
//   * Threat-intel feeds are noisy.  Hits are treated as a *bonus*
//     to the final risk, not as the sole basis for a verdict:
//     `AnalysisResult.FeedHits` populates `ScoreContributors` with
//     `Bonus:IntelFeed:<name>` so the UI can show why the score
//     went up.  A clean binary that happens to embed a long-expired
//     URL still relies on behavioural signals to land in HIGH.
// ─────────────────────────────────────────────────────────────────

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
    // Public surface — config record + indicator pool
    // -----------------------------------------------------------------

    /// <summary>
    /// JSON-shaped config for a single feed entry.
    /// </summary>
    public sealed class ThreatIntelFeedConfig
    {
        [JsonPropertyName("name")]      public string Name      { get; set; } = "";
        [JsonPropertyName("format")]    public string Format    { get; set; } = "";
        [JsonPropertyName("source")]    public string Source    { get; set; } = "";
        [JsonPropertyName("ttl_hours")] public int    TtlHours  { get; set; } = 6;
    }

    /// <summary>
    /// Aggregated indicator pool across all configured feeds.  All
    /// HashSets use OrdinalIgnoreCase so case-insensitive matches
    /// against extracted strings work without re-lowercasing.
    /// </summary>
    public sealed class ThreatIntelFeedPool
    {
        public HashSet<string> Sha256s    { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Urls       { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Ipv4s      { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Domains    { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Imphashes  { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> TlshLines  { get; } = new(StringComparer.OrdinalIgnoreCase);

        // origin tag per indicator: "<feedname>"
        public Dictionary<string, string> Origin { get; } = new(StringComparer.OrdinalIgnoreCase);

        public int Total => Sha256s.Count + Urls.Count + Ipv4s.Count + Domains.Count + Imphashes.Count + TlshLines.Count;
    }

    public sealed class ThreatIntelFeedRefreshSummary
    {
        public string Name   { get; init; } = "";
        public bool   Used   { get; init; }           // false == cached, true == fetched & parsed
        public int    Loaded { get; init; }           // total indicators after parse
        public string Error  { get; init; } = "";
    }

    /// <summary>
    /// Reads feed config, fetches each feed (HTTP or `file:///`), parses
    /// known formats, and exposes the merged indicator pool.
    /// </summary>
    public sealed class ThreatIntelFeedManager
    {
        private readonly string _configPath;
        private readonly string _cacheDir;
        private readonly HttpClient _http;
        private readonly object _gate = new();
        private ThreatIntelFeedPool _pool = new();

        public ThreatIntelFeedPool Pool => _pool;
        public DateTime LastRefreshUtc { get; private set; }

        public ThreatIntelFeedManager(string configPath, string cacheDir,
                                      HttpMessageHandler? handler = null)
        {
            _configPath = configPath;
            _cacheDir   = cacheDir;
            _http       = handler != null
                ? new HttpClient(handler, disposeHandler: false)
                : new HttpClient();
            _http.Timeout = TimeSpan.FromSeconds(15);
        }

        /// <summary>
        /// Read the feed config from disk.  Missing / unreadable config
        /// returns an empty list — callers should treat that as
        /// "feature disabled".
        /// </summary>
        public List<ThreatIntelFeedConfig> LoadConfig()
        {
            try
            {
                if (!File.Exists(_configPath)) return new();
                var text = File.ReadAllText(_configPath);
                var list = JsonSerializer.Deserialize<List<ThreatIntelFeedConfig>>(
                    text,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                return list ?? new();
            }
            catch { return new(); }
        }

        /// <summary>
        /// Refresh each configured feed.  Feeds whose on-disk cache is
        /// younger than `ttl_hours` are not re-fetched.  Returns a
        /// per-feed summary so a CLI / UI can render the status table.
        /// </summary>
        public async Task<List<ThreatIntelFeedRefreshSummary>> RefreshAsync(bool force, CancellationToken ct)
        {
            var summaries = new List<ThreatIntelFeedRefreshSummary>();
            var configs   = LoadConfig();
            if (configs.Count == 0) return summaries;

            try { Directory.CreateDirectory(_cacheDir); } catch { /* best-effort */ }

            var fresh = new ThreatIntelFeedPool();

            foreach (var cfg in configs)
            {
                if (string.IsNullOrWhiteSpace(cfg.Name) || string.IsNullOrWhiteSpace(cfg.Source))
                {
                    summaries.Add(new ThreatIntelFeedRefreshSummary { Name = cfg.Name, Error = "invalid_config" });
                    continue;
                }
                var idxPath  = Path.Combine(_cacheDir, SafeName(cfg.Name) + ".idx");
                var metaPath = Path.Combine(_cacheDir, SafeName(cfg.Name) + ".meta");

                bool fetched = false;
                string error = "";
                try
                {
                    bool stale = force || IsCacheStale(metaPath, cfg.TtlHours);
                    string raw = stale
                        ? await FetchAsync(cfg.Source, ct)
                        : SafeReadAllText(idxPath, raw: false) ?? string.Empty;
                    if (stale && raw.Length == 0) error = "fetch_empty";

                    var parsed = stale ? Parse(cfg, raw) : Lines(raw);
                    if (stale)
                    {
                        // Persist canonicalised indicators for next run.
                        try
                        {
                            File.WriteAllLines(idxPath, parsed);
                            File.WriteAllText(metaPath, DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));
                        }
                        catch { /* best-effort */ }
                        fetched = true;
                    }
                    MergeIntoPool(fresh, cfg.Name, parsed);
                    summaries.Add(new ThreatIntelFeedRefreshSummary
                    {
                        Name   = cfg.Name,
                        Used   = fetched,
                        Loaded = parsed.Count,
                        Error  = error,
                    });
                }
                catch (Exception ex)
                {
                    summaries.Add(new ThreatIntelFeedRefreshSummary
                    {
                        Name = cfg.Name,
                        Error = ex.GetType().Name,
                    });
                }
            }

            lock (_gate)
            {
                _pool = fresh;
                LastRefreshUtc = DateTime.UtcNow;
            }
            return summaries;
        }

        /// <summary>
        /// Test seam — replace the live pool without touching the disk
        /// cache or the network.  Used by `IntelProvidersTests` and
        /// by the synthetic regression corpus.
        /// </summary>
        internal void OverrideForTesting(ThreatIntelFeedPool pool)
        {
            lock (_gate) { _pool = pool ?? new(); LastRefreshUtc = DateTime.UtcNow; }
        }

        // ─────────────────────────────────────────────────────────
        //  Parsers
        // ─────────────────────────────────────────────────────────

        /// <summary>
        /// Convert a raw feed body into a list of `kind:value` lines
        /// using the configured format.  Unknown formats fall through
        /// to the plain-text classifier.
        /// </summary>
        public static List<string> Parse(ThreatIntelFeedConfig cfg, string body)
        {
            if (string.IsNullOrEmpty(body)) return new();
            switch ((cfg.Format ?? "").ToLowerInvariant())
            {
                case "stix":         return ParseStix(body);
                case "urlhaus_csv":  return ParseUrlhausCsv(body);
                case "threatfox_csv":return ParseThreatFoxCsv(body);
                case "mb_csv":       return ParseMalwareBazaarCsv(body);
                case "plain":
                default:             return ParsePlain(body);
            }
        }

        internal static List<string> ParsePlain(string body)
        {
            var ind = new List<string>();
            foreach (var raw in body.Split('\n'))
            {
                var line = raw.Trim().TrimEnd('\r');
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
                var kv = Classify(line);
                if (kv.Length > 0) ind.Add(kv);
            }
            return ind;
        }

        internal static List<string> ParseUrlhausCsv(string body)
        {
            // URLhaus CSV columns: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
            var ind = new List<string>();
            foreach (var raw in body.Split('\n'))
            {
                var line = raw.TrimEnd('\r');
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
                var cols = SplitCsvRespectingQuotes(line);
                if (cols.Count < 3) continue;
                var url = StripQuotes(cols[2]);
                if (url.Length > 0 && (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                                       url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)))
                {
                    ind.Add("url:" + url);
                }
            }
            return ind;
        }

        internal static List<string> ParseThreatFoxCsv(string body)
        {
            // ThreatFox CSV: first_seen_utc,ioc_id,ioc_value,ioc_type,threat_type,malware,...
            var ind = new List<string>();
            foreach (var raw in body.Split('\n'))
            {
                var line = raw.TrimEnd('\r');
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
                var cols = SplitCsvRespectingQuotes(line);
                if (cols.Count < 4) continue;
                var value = StripQuotes(cols[2]);
                var kind  = StripQuotes(cols[3]).ToLowerInvariant();
                if (value.Length == 0) continue;
                switch (kind)
                {
                    case "sha256_hash":
                    case "sha256":         if (value.Length == 64) ind.Add("sha256:" + value); break;
                    case "url":            ind.Add("url:" + value); break;
                    case "ip:port":
                    case "ipv4":           ind.Add("ipv4:" + value.Split(':')[0]); break;
                    case "domain":         ind.Add("domain:" + value); break;
                    case "imphash":        ind.Add("imphash:" + value); break;
                    case "tlsh":           ind.Add("tlsh:" + value); break;
                }
            }
            return ind;
        }

        internal static List<string> ParseMalwareBazaarCsv(string body)
        {
            // MalwareBazaar `recent` CSV: first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,file_type_guess,...
            var ind = new List<string>();
            foreach (var raw in body.Split('\n'))
            {
                var line = raw.TrimEnd('\r');
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
                var cols = SplitCsvRespectingQuotes(line);
                if (cols.Count < 2) continue;
                var sha = StripQuotes(cols[1]).ToLowerInvariant();
                if (sha.Length == 64 && IsHex(sha))
                    ind.Add("sha256:" + sha);
            }
            return ind;
        }

        internal static List<string> ParseStix(string body)
        {
            // Very small STIX 2.x indicator-pattern reader.  We do not
            // pull a full STIX library — the pattern grammar is well
            // bounded for SHA-256 / URL / IPv4 / DomainName indicators,
            // and the few CISA advisories we want to ingest all use
            // those forms.
            var ind = new List<string>();
            try
            {
                using var doc = JsonDocument.Parse(body);
                if (!doc.RootElement.TryGetProperty("objects", out var objects)) return ind;
                foreach (var obj in objects.EnumerateArray())
                {
                    if (!obj.TryGetProperty("type", out var type) || type.GetString() != "indicator") continue;
                    if (!obj.TryGetProperty("pattern", out var patt)) continue;
                    var pattern = patt.GetString() ?? "";
                    if (string.IsNullOrEmpty(pattern)) continue;

                    // file:hashes.'SHA-256' = '<hex>'
                    TryExtractAfter(pattern, "hashes.'SHA-256' = '",  ind, "sha256");
                    TryExtractAfter(pattern, "hashes.\"SHA-256\" = '", ind, "sha256");
                    // url:value = '<url>'
                    TryExtractAfter(pattern, "url:value = '", ind, "url");
                    // ipv4-addr:value = '<addr>'
                    TryExtractAfter(pattern, "ipv4-addr:value = '", ind, "ipv4");
                    // domain-name:value = '<host>'
                    TryExtractAfter(pattern, "domain-name:value = '", ind, "domain");
                }
            }
            catch { /* malformed STIX is silently ignored */ }
            return ind;
        }

        // Extracts the value between the first pair of single quotes
        // immediately after `needle`.  Reused by ParseStix() for each
        // SDO pattern kind (sha256 / url / ipv4 / domain).
        private static void TryExtractAfter(string pattern, string needle, List<string> ind, string kind)
        {
            int p = pattern.IndexOf(needle, StringComparison.OrdinalIgnoreCase);
            if (p < 0) return;
            int valueStart = p + needle.Length;        // first char of the value (needle ends with `'`)
            int valueEnd   = pattern.IndexOf('\'', valueStart);
            if (valueEnd <= valueStart) return;
            var value = pattern.Substring(valueStart, valueEnd - valueStart);
            if (value.Length == 0) return;
            if (kind == "sha256") value = value.ToLowerInvariant();
            ind.Add(kind + ":" + value);
        }

        // ─────────────────────────────────────────────────────────
        //  Helpers
        // ─────────────────────────────────────────────────────────

        private bool IsCacheStale(string metaPath, int ttlHours)
        {
            try
            {
                if (!File.Exists(metaPath)) return true;
                var ts = File.ReadAllText(metaPath).Trim();
                if (!DateTime.TryParse(ts, CultureInfo.InvariantCulture,
                                       DateTimeStyles.RoundtripKind, out var when))
                    return true;
                return DateTime.UtcNow - when > TimeSpan.FromHours(Math.Max(1, ttlHours));
            }
            catch { return true; }
        }

        private async Task<string> FetchAsync(string source, CancellationToken ct)
        {
            if (source.StartsWith("file:///", StringComparison.OrdinalIgnoreCase))
            {
                // file:// URIs come in three shapes:
                //   * file:///etc/foo            (Linux absolute)
                //   * file:///C:/path/foo        (Windows drive)
                //   * file:////tmp/foo           (4-slash variant generated by
                //                                 callers that concat file:/// + abs path)
                // Try the path-after-scheme first (handles 4-slash on Linux),
                // then fall back to Uri.LocalPath (handles Windows drives).
                var candidates = new System.Collections.Generic.List<string>();
                var afterScheme = source.Substring("file://".Length);
                candidates.Add(afterScheme);
                if (afterScheme.Length > 1) candidates.Add(afterScheme.TrimStart('/'));
                try { candidates.Add(new Uri(source).LocalPath); } catch { }
                foreach (var p in candidates)
                {
                    if (string.IsNullOrEmpty(p)) continue;
                    if (File.Exists(p)) return await File.ReadAllTextAsync(p, ct);
                }
                return string.Empty;
            }
            try
            {
                using var resp = await _http.GetAsync(source, HttpCompletionOption.ResponseHeadersRead, ct);
                if (!resp.IsSuccessStatusCode) return string.Empty;
                var bytes = await resp.Content.ReadAsByteArrayAsync(ct);
                if (bytes.Length > 16_777_216) Array.Resize(ref bytes, 16_777_216); // 16 MiB cap
                return Encoding.UTF8.GetString(bytes);
            }
            catch { return string.Empty; }
        }

        private static void MergeIntoPool(ThreatIntelFeedPool pool, string feedName, List<string> indicators)
        {
            foreach (var line in indicators)
            {
                int colon = line.IndexOf(':');
                if (colon < 1) continue;
                var kind  = line.Substring(0, colon).ToLowerInvariant();
                var value = line.Substring(colon + 1).Trim();
                if (value.Length == 0) continue;
                bool added = kind switch
                {
                    "sha256"  => pool.Sha256s.Add(value),
                    "url"     => pool.Urls.Add(value),
                    "ipv4"    => pool.Ipv4s.Add(value),
                    "domain"  => pool.Domains.Add(value),
                    "imphash" => pool.Imphashes.Add(value),
                    "tlsh"    => pool.TlshLines.Add(value),
                    _         => false,
                };
                if (added)
                {
                    var key = kind + ":" + value;
                    if (!pool.Origin.ContainsKey(key))
                        pool.Origin[key] = feedName;
                }
            }
        }

        private static List<string> Lines(string body)
        {
            if (string.IsNullOrEmpty(body)) return new();
            var list = new List<string>();
            foreach (var raw in body.Split('\n'))
            {
                var line = raw.Trim().TrimEnd('\r');
                if (line.Length > 0 && !line.StartsWith("#", StringComparison.Ordinal)) list.Add(line);
            }
            return list;
        }

        private static string SafeName(string n)
        {
            var sb = new StringBuilder();
            foreach (var c in n)
            {
                if (char.IsLetterOrDigit(c) || c == '-' || c == '_') sb.Append(c);
                else sb.Append('_');
            }
            return sb.Length == 0 ? "feed" : sb.ToString();
        }

        private static string? SafeReadAllText(string p, bool raw)
        {
            try { return File.Exists(p) ? File.ReadAllText(p) : null; }
            catch { return null; }
        }

        private static List<string> SplitCsvRespectingQuotes(string line)
        {
            var cols = new List<string>();
            var sb   = new StringBuilder();
            bool quoted = false;
            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (c == '"') { quoted = !quoted; sb.Append(c); }
                else if (c == ',' && !quoted) { cols.Add(sb.ToString()); sb.Clear(); }
                else sb.Append(c);
            }
            cols.Add(sb.ToString());
            return cols;
        }

        private static string StripQuotes(string s)
        {
            var t = s.Trim();
            if (t.Length >= 2 && t[0] == '"' && t[t.Length - 1] == '"')
                return t.Substring(1, t.Length - 2);
            return t;
        }

        private static string Classify(string line)
        {
            // sha256
            if (line.Length == 64 && IsHex(line)) return "sha256:" + line.ToLowerInvariant();
            // url
            if (line.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                return "url:" + line;
            // imphash (md5 hex, 32)
            if (line.Length == 32 && IsHex(line)) return "imphash:" + line.ToLowerInvariant();
            // tlsh (35 + "T1" prefix or 70 hex)
            if (line.Length >= 35 && (line.StartsWith("T1", StringComparison.OrdinalIgnoreCase) || line.StartsWith("T", StringComparison.OrdinalIgnoreCase)))
                return "tlsh:" + line;
            // ipv4
            if (IsIpv4(line)) return "ipv4:" + line;
            // domain
            if (line.IndexOf('.') > 0 && !line.Any(char.IsWhiteSpace)) return "domain:" + line;
            return "";
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
    }

    /// <summary>
    /// Process-wide singleton pool of auto-ingested threat-intel feeds.
    /// Loaded lazily from `<exe-dir>/intel/feeds.json` on first access;
    /// tests override with <see cref="OverrideForTesting"/>.
    /// </summary>
    public static class ThreatIntelFeedRegistry
    {
        private static readonly object _lock = new();
        private static ThreatIntelFeedPool _pool = new();
        private static bool _initialised;

        public static ThreatIntelFeedPool Pool
        {
            get
            {
                EnsureInit();
                return _pool;
            }
        }

        /// <summary>
        /// Test seam.  Replaces the in-memory pool without touching the
        /// filesystem.  Call <see cref="ResetForTesting"/> afterwards to
        /// allow re-initialisation on next access.
        /// </summary>
        public static void OverrideForTesting(ThreatIntelFeedPool pool)
        {
            lock (_lock)
            {
                _pool        = pool ?? new();
                _initialised = true;
            }
        }

        public static void ResetForTesting()
        {
            lock (_lock)
            {
                _pool        = new();
                _initialised = false;
            }
        }

        private static void EnsureInit()
        {
            if (_initialised) return;
            lock (_lock)
            {
                if (_initialised) return;
                _initialised = true;
                try
                {
                    string? exeDir = Path.GetDirectoryName(
                        System.Reflection.Assembly.GetExecutingAssembly().Location);
                    if (string.IsNullOrEmpty(exeDir)) return;
                    string cfg   = Path.Combine(exeDir, "intel", "feeds.json");
                    string cache = Path.Combine(exeDir, "intel", "cache");
                    if (!File.Exists(cfg)) return;
                    var mgr = new ThreatIntelFeedManager(cfg, cache);
                    // Synchronous best-effort refresh — only cached
                    // entries (whose TTL is fresh) are actually loaded
                    // here.  Stale entries are skipped to avoid
                    // blocking Analyze() on a network call.
                    var summary = mgr.RefreshAsync(force: false, default).GetAwaiter().GetResult();
                    _pool = mgr.Pool;
                    _ = summary; // discard — diagnostics live in the manager instance.
                }
                catch
                {
                    // Best-effort.  Missing / unreadable config disables
                    // the feature without breaking analysis.
                }
            }
        }
    }

    /// <summary>
    /// Public extension class — wires the feed pool into the analyzer
    /// pipeline.  Called from `Analyzer.Analyze` after the IOC pass.
    /// </summary>
    public static class ThreatIntelFeedMatcher
    {
        public static void Apply(AnalysisResult r) => Apply(r, ThreatIntelFeedRegistry.Pool);

        public static void Apply(AnalysisResult r, ThreatIntelFeedPool pool)
        {
            if (r == null || pool == null) return;
            if (pool.Total == 0) return;

            // sha256 — always lower-case in the pool.
            if (!string.IsNullOrEmpty(r.Sha256))
            {
                var sha = r.Sha256.ToLowerInvariant();
                if (pool.Sha256s.Contains(sha))
                    Add(r, pool, "sha256", sha);
            }

            // imphash — same canonicalisation rules as the curated DB.
            if (!string.IsNullOrEmpty(r.ImpHash))
            {
                var imp = r.ImpHash.ToLowerInvariant();
                if (pool.Imphashes.Contains(imp))
                    Add(r, pool, "imphash", imp);
            }

            // urls — exact string match (URLhaus / CISA STIX url:value).
            foreach (var u in r.UrlsFound)
            {
                if (u == null) continue;
                if (pool.Urls.Contains(u))
                    Add(r, pool, "url", u);
                // domain — best-effort host extraction.
                var host = ExtractHost(u);
                if (host.Length > 0 && pool.Domains.Contains(host))
                    Add(r, pool, "domain", host);
            }

            // ipv4 hits.
            foreach (var ip in r.Ipv4Hits)
            {
                if (ip != null && pool.Ipv4s.Contains(ip))
                    Add(r, pool, "ipv4", ip);
            }
        }

        private static void Add(AnalysisResult r, ThreatIntelFeedPool pool, string kind, string value)
        {
            var feedKey = kind + ":" + value;
            pool.Origin.TryGetValue(feedKey, out var origin);
            var entry = (origin ?? "intel") + "|" + feedKey;
            if (!r.FeedHits.Contains(entry, StringComparer.OrdinalIgnoreCase))
                r.FeedHits.Add(entry);
        }

        private static string ExtractHost(string url)
        {
            int p = url.IndexOf("://", StringComparison.Ordinal);
            int start = p >= 0 ? p + 3 : 0;
            int end = url.IndexOfAny(new[] { '/', ':', '?', '#' }, start);
            if (end < 0) end = url.Length;
            return url.Substring(start, end - start).ToLowerInvariant();
        }
    }
}
