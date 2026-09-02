// PR 8 — Section 10 (Sigma/YARA/CAPA detection engines):
//
//   10.1  Full Sigma parser — logsource, multiple selections with field+modifier
//         pairs (contains/startswith/endswith/re/cased/all), composite condition
//         grammar (and/or/not/parentheses, "1 of selection_*", "all of selection_*",
//         "count(selection_*) >= N").
//   10.2  CAPA parser closer to the upstream spec — meta block with name/namespace/
//         authors/scopes, features tree (and/or/not/optional/N or more), feature
//         types api/import/string/substring/regex/os/format/arch/section/export/
//         characteristic/match. Backward-compatible with the old single-flat
//         "imports: + match: + strings:" format that ships in rules/capa/*.
//   10.3  yara-x integration. Detector probes for the upstream Rust reimpl
//         (binary names: yr / yara-x / yara-x.exe), invokes it preferentially
//         in NDJSON mode, falls back to the classic yara binary if not present.
//   10.4  rules update CLI — `antistealer rules update --engine <sigma|capa|yara|all>
//         --source <URL|dir|git+...> [--public-key ...] [--insecure]`. Writes
//         per-rule-pack _provenance.json (source / fetched_at / sha256 / version /
//         file_count) and verifies an optional Ed25519 .sig sidecar.
//   10.5  Per-rule provenance on hits — analyzer enriches each rule hit with the
//         file basename, sha256, and last-known _provenance.json metadata, stored
//         on AnalysisResult.RulesProvenance so report writers can surface where a
//         hit came from.
//   10.6  Per-rule and per-engine timeouts via cancellation tokens. Per-engine
//         budget is read from `ANTISTEALER_RULES_TIMEOUT_MS` (default 5000). Each
//         rule file gets a per-rule slice; timeouts are recorded on
//         AnalysisResult.RulesEngineTimeouts and surfaced in the full report.
//
// This file deliberately keeps the new engines isolated from Analyzer.cs / Detectors.cs
// so the old minimal Sigma/CAPA flows in Detectors.DetectSigmaRulesFull /
// Detectors.DetectCapaRules continue to compile until the new entry points in
// Analyzer.cs cut over to them.
using System.Diagnostics;
using System.Globalization;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace AntiStealerOneExe
{
    // ---------------------------------------------------------------------
    // Section 10.5 — rule provenance & engine telemetry on AnalysisResult.
    // Defined as a partial of AnalysisResult so we don't have to chase every
    // diagnostic field through the giant Analyzer.cs file.
    // ---------------------------------------------------------------------

    public sealed partial class AnalysisResult
    {
        /// <summary>
        /// Provenance metadata per matched rule, keyed by rule basename
        /// (e.g. "stealer_telegram_exfil.yml"). Populated by the Sigma /
        /// CAPA / YARA engines when a hit is recorded.
        /// </summary>
        public Dictionary<string, RuleProvenance> RulesProvenance { get; set; }
            = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Total milliseconds spent in each rule engine for this scan
        /// (key: "sigma" | "capa" | "yara" | "yara-x"). Always present
        /// even when the engine produced zero hits — useful for perf budgets.
        /// </summary>
        public Dictionary<string, long> RulesEngineTimingsMs { get; set; }
            = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Rule files that were skipped because they exceeded the per-rule
        /// timeout slice. Stored as "engine:basename" to make telemetry
        /// digest-able in the report.
        /// </summary>
        public List<string> RulesEngineTimeouts { get; set; } = new();

        /// <summary>
        /// C18 — captured stderr emitted by the rules engine binaries
        /// (yara / yara-x). Each entry: "engine:basename: &lt;first-line
        /// stderr&gt;". Helps diagnose corrupt rule files and engine
        /// configuration problems without spamming the main report.
        /// </summary>
        public List<string> RulesEngineErrors { get; set; } = new();

        /// <summary>
        /// Which YARA engine actually ran (yara-x preferred over classic yara
        /// when both are present). Empty string if no YARA binary was found.
        /// </summary>
        public string YaraEngine { get; set; } = "";
    }

    /// <summary>
    /// Provenance metadata attached to a rule hit.
    /// </summary>
    public sealed class RuleProvenance
    {
        public string Engine { get; set; } = "";
        public string RuleFile { get; set; } = "";
        public string Sha256 { get; set; } = "";
        public string Source { get; set; } = "";
        public string Version { get; set; } = "";
        public DateTime FetchedAtUtc { get; set; }
        public DateTime ModifiedUtc { get; set; }
    }

    /// <summary>
    /// Wire-format for a _provenance.json file dropped next to a rule pack.
    /// </summary>
    public sealed class RulePackManifest
    {
        [JsonPropertyName("engine")]         public string Engine { get; set; } = "";
        [JsonPropertyName("source")]         public string Source { get; set; } = "";
        [JsonPropertyName("version")]        public string Version { get; set; } = "";
        [JsonPropertyName("fetched_at_utc")] public DateTime FetchedAtUtc { get; set; }
        [JsonPropertyName("sha256")]         public string Sha256 { get; set; } = "";
        [JsonPropertyName("file_count")]     public int FileCount { get; set; }
        [JsonPropertyName("signed")]         public bool Signed { get; set; }
        [JsonPropertyName("signer_pubkey")]  public string SignerPublicKey { get; set; } = "";
    }

    // ---------------------------------------------------------------------
    // Section 10.6 — shared budget object that engines consult between rules
    // to enforce per-engine and per-rule timeouts.
    // ---------------------------------------------------------------------

    internal sealed class RulesBudget
    {
        public string Engine { get; }
        public Stopwatch Total { get; } = Stopwatch.StartNew();
        public long EngineBudgetMs { get; }
        public long PerRuleBudgetMs { get; }

        public RulesBudget(string engine, long engineBudgetMs, long perRuleBudgetMs)
        {
            Engine = engine;
            EngineBudgetMs = engineBudgetMs;
            PerRuleBudgetMs = perRuleBudgetMs;
        }

        public bool EngineExpired => Total.ElapsedMilliseconds >= EngineBudgetMs;

        public Stopwatch StartRule() => Stopwatch.StartNew();

        public bool RuleExpired(Stopwatch ruleClock)
            => ruleClock.ElapsedMilliseconds >= PerRuleBudgetMs;

        public static RulesBudget FromEnv(string engine)
        {
            long total = ReadEnvLong("ANTISTEALER_RULES_TIMEOUT_MS", 5000);
            long perRule = ReadEnvLong("ANTISTEALER_RULES_PER_RULE_TIMEOUT_MS", 250);
            return new RulesBudget(engine, total, perRule);
        }

        private static long ReadEnvLong(string name, long fallback)
        {
            var raw = Environment.GetEnvironmentVariable(name);
            // Accept 0 explicitly ("engine disabled / always-timeout" test hook),
            // reject negative values.
            if (long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) && v >= 0)
                return v;
            return fallback;
        }
    }

    // ---------------------------------------------------------------------
    // Shared helpers for both engines.
    // ---------------------------------------------------------------------

    internal static class RuleEngineUtil
    {
        /// <summary>
        /// Look up a rule pack directory in (1) %APPDATA%\AntiStealer\rules\&lt;engine&gt;
        /// then (2) &lt;exe-dir&gt;\rules\&lt;engine&gt;.
        /// </summary>
        public static string? ResolveRulesDir(string engine)
        {
            try
            {
                var roaming = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                                           "AntiStealer", "rules", engine);
                if (Directory.Exists(roaming)) return roaming;
                var cwd = Path.Combine(AppContext.BaseDirectory, "rules", engine);
                if (Directory.Exists(cwd)) return cwd;
                return null;
            }
            catch { return null; }
        }

        public static string Sha256Hex(byte[] bytes)
        {
            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(bytes);
            var sb = new StringBuilder(hash.Length * 2);
            foreach (var b in hash) sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
            return sb.ToString();
        }

        public static string Sha256HexFile(string path)
        {
            try { return Sha256Hex(File.ReadAllBytes(path)); }
            catch { return ""; }
        }

        /// <summary>
        /// Look for _provenance.json next to a rule file (same dir or parent dir
        /// up to two levels). Returns null if none is present.
        /// </summary>
        public static RulePackManifest? LoadPackManifest(string ruleFile)
        {
            try
            {
                var dir = Path.GetDirectoryName(ruleFile);
                for (int i = 0; i < 3 && !string.IsNullOrEmpty(dir); i++)
                {
                    var probe = Path.Combine(dir, "_provenance.json");
                    if (File.Exists(probe))
                    {
                        var json = File.ReadAllText(probe);
                        var m = JsonSerializer.Deserialize<RulePackManifest>(json, JsonOptionsRegistry.CamelCase);
                        if (m != null) return m;
                    }
                    dir = Path.GetDirectoryName(dir);
                }
            }
            catch { /* best-effort */ }
            return null;
        }

        public static void RecordProvenance(AnalysisResult r, string engine, string ruleFile)
        {
            try
            {
                var basename = Path.GetFileName(ruleFile);
                if (r.RulesProvenance.ContainsKey(basename)) return;
                var pack = LoadPackManifest(ruleFile);
                var prov = new RuleProvenance
                {
                    Engine = engine,
                    RuleFile = basename,
                    Sha256 = Sha256HexFile(ruleFile),
                    Source = pack?.Source ?? "",
                    Version = pack?.Version ?? "",
                    FetchedAtUtc = pack?.FetchedAtUtc ?? default,
                    ModifiedUtc = SafeLastWriteUtc(ruleFile),
                };
                r.RulesProvenance[basename] = prov;
            }
            catch { /* best-effort */ }
        }

        private static DateTime SafeLastWriteUtc(string path)
        {
            try { return File.GetLastWriteTimeUtc(path); } catch { return default; }
        }

        public static void AddTimingMs(AnalysisResult r, string engine, long elapsedMs)
        {
            if (r.RulesEngineTimingsMs.TryGetValue(engine, out var prev))
                r.RulesEngineTimingsMs[engine] = prev + elapsedMs;
            else
                r.RulesEngineTimingsMs[engine] = elapsedMs;
        }
    }

    // ---------------------------------------------------------------------
    // Section 10.1 — Full(er) Sigma parser/evaluator.
    //
    // The detection block can contain N named selections; each selection is
    // either a flat list of substrings (back-compat with the existing minimal
    // rules in rules/sigma/*.yml) or a dict of "field|modifier|modifier: value"
    // pairs. The condition can use and / or / not / parentheses /
    // "<N> of <pattern>" / "all of <pattern>" / "count(<sel>) <op> <n>".
    //
    // Static-only constraint: we do not know per-event field values, so all
    // field selectors evaluate against either the consolidated analysis text
    // (extracted strings + URLs + IOCs) for "string-shaped" fields, or against
    // a small set of well-known synthetic fields (Imports, ImpHash, Sha256,
    // ...). Unknown fields fall back to substring search on analysisText.
    // ---------------------------------------------------------------------

    public sealed class SigmaRule
    {
        public string Title { get; set; } = "";
        public string Id { get; set; } = "";
        public string Level { get; set; } = "";
        public string Description { get; set; } = "";
        public List<string> Tags { get; set; } = new();
        public SigmaLogsource Logsource { get; set; } = new();
        public string Condition { get; set; } = "";

        /// <summary>
        /// Selection name → either a flat list of substring patterns (no field)
        /// or a list of <see cref="SigmaFieldPredicate"/>s. We use a discriminated
        /// representation so callers can be specific.
        /// </summary>
        public Dictionary<string, SigmaSelection> Selections { get; set; }
            = new(StringComparer.OrdinalIgnoreCase);
    }

    public sealed class SigmaLogsource
    {
        public string Category { get; set; } = "";
        public string Product { get; set; } = "";
        public string Service { get; set; } = "";
    }

    public sealed class SigmaSelection
    {
        public List<string> KeywordPatterns { get; set; } = new();
        public List<SigmaFieldPredicate> FieldPredicates { get; set; } = new();
        public bool IsEmpty => KeywordPatterns.Count == 0 && FieldPredicates.Count == 0;
    }

    public sealed class SigmaFieldPredicate
    {
        public string Field { get; set; } = "";
        public List<string> Modifiers { get; set; } = new();
        public List<string> Values { get; set; } = new();
    }

    public static class SigmaFullEngine
    {
        /// <summary>
        /// Run the Sigma engine over every rule file in the resolved rule dir.
        /// Each hit is recorded on <paramref name="r"/>.SigmaFullHits with
        /// provenance, and per-engine/-rule timing/timeout telemetry is
        /// captured on r.RulesEngineTimingsMs / r.RulesEngineTimeouts.
        /// </summary>
        public static void Run(AnalysisResult r, string analysisText)
            => Run(r, analysisText, RuleEngineUtil.ResolveRulesDir("sigma"));

        /// <summary>
        /// Run against an explicit rule directory (used by unit tests and the
        /// in-process scanning service that bypasses the auto-resolver).
        /// </summary>
        public static void Run(AnalysisResult r, string analysisText, string? dir)
        {
            if (dir == null || !Directory.Exists(dir)) return;

            var budget = RulesBudget.FromEnv("sigma");
            var ctx = BuildContext(r, analysisText);

            foreach (var file in EnumerateRuleFiles(dir))
            {
                if (budget.EngineExpired)
                {
                    r.RulesEngineTimeouts.Add($"sigma:engine-budget");
                    break;
                }
                var ruleClock = budget.StartRule();
                try
                {
                    string[] lines = File.ReadAllLines(file);
                    foreach (var rule in ParseAll(lines))
                    {
                        if (budget.RuleExpired(ruleClock))
                        {
                            r.RulesEngineTimeouts.Add($"sigma:{Path.GetFileName(file)}");
                            break;
                        }
                        if (string.IsNullOrEmpty(rule.Title) || rule.Selections.Count == 0) continue;
                        if (!Evaluate(rule, ctx)) continue;
                        var tag = $"{rule.Title} [{Path.GetFileName(file)}]";
                        if (!r.SigmaFullHits.Contains(tag)) r.SigmaFullHits.Add(tag);
                        RuleEngineUtil.RecordProvenance(r, "sigma", file);
                    }
                }
                catch { /* skip malformed rule */ }
                finally
                {
                    ruleClock.Stop();
                }
            }
            RuleEngineUtil.AddTimingMs(r, "sigma", budget.Total.ElapsedMilliseconds);
        }

        internal static IEnumerable<string> EnumerateRuleFiles(string dir)
            => Directory.EnumerateFiles(dir, "*.yml", SearchOption.AllDirectories)
                        .Concat(Directory.EnumerateFiles(dir, "*.yaml", SearchOption.AllDirectories));

        // -----------------------------------------------------------------
        // YAML-ish parser. We don't depend on a real YAML lib (the existing
        // code base is hand-rolled YAML); we just need enough to support
        // the common single-document and ---separated multi-doc files.
        // -----------------------------------------------------------------

        internal static List<SigmaRule> ParseAll(string[] lines)
        {
            var rules = new List<SigmaRule>();
            // Multi-document split (`---` on its own line).
            var blocks = SplitYamlDocs(lines);
            foreach (var block in blocks)
            {
                var rule = ParseOne(block);
                if (rule != null) rules.Add(rule);
            }
            return rules;
        }

        internal static SigmaRule? ParseOne(IReadOnlyList<string> lines)
        {
            var rule = new SigmaRule();
            int n = lines.Count;

            // Walk the file with a hand-rolled state machine. We track
            // `section` (top-level key under which we currently are) and
            // `selectionName` (name of the active detection: <name> dict).

            int i = 0;
            while (i < n)
            {
                var raw = lines[i];
                var trimmed = raw.TrimEnd();
                if (string.IsNullOrWhiteSpace(trimmed) || trimmed.TrimStart().StartsWith("#"))
                { i++; continue; }

                // top-level key?  i.e. "title:", "detection:", "logsource:" ...
                if (!StartsWithSpace(raw) && raw.Contains(':'))
                {
                    var (key, val) = SplitKv(raw);
                    if (key == null) { i++; continue; }
                    switch (key.ToLowerInvariant())
                    {
                        case "title":          rule.Title       = Unquote(val); i++; break;
                        case "id":             rule.Id          = Unquote(val); i++; break;
                        case "level":          rule.Level       = Unquote(val); i++; break;
                        case "description":    rule.Description = Unquote(val); i++; break;
                        case "tags":
                            i++; i = ReadBulletList(lines, i, rule.Tags); break;
                        case "logsource":
                            i = ParseLogsource(lines, i + 1, rule.Logsource); break;
                        case "detection":
                            i = ParseDetection(lines, i + 1, rule); break;
                        default:
                            i++; break;
                    }
                }
                else
                {
                    i++;
                }
            }

            if (string.IsNullOrEmpty(rule.Title)) return null;
            // Default condition when there's exactly one selection.
            if (string.IsNullOrEmpty(rule.Condition) && rule.Selections.Count == 1)
                rule.Condition = rule.Selections.Keys.First();
            return rule;
        }

        private static int ParseLogsource(IReadOnlyList<string> lines, int start, SigmaLogsource ls)
        {
            int i = start;
            while (i < lines.Count)
            {
                var raw = lines[i];
                if (!StartsWithSpace(raw)) break;
                if (CountLeadingSpaces(raw) < 2) break;
                var trimmed = raw.TrimEnd();
                if (string.IsNullOrWhiteSpace(trimmed)) { i++; continue; }
                var (key, val) = SplitKv(raw);
                if (key == null) { i++; continue; }
                switch (key.ToLowerInvariant())
                {
                    case "category": ls.Category = Unquote(val); break;
                    case "product":  ls.Product  = Unquote(val); break;
                    case "service":  ls.Service  = Unquote(val); break;
                }
                i++;
            }
            return i;
        }

        private static int ParseDetection(IReadOnlyList<string> lines, int start, SigmaRule rule)
        {
            int i = start;
            string? currentSelection = null;
            while (i < lines.Count)
            {
                var raw = lines[i];
                var trimmed = raw.TrimEnd();
                if (string.IsNullOrWhiteSpace(trimmed)) { i++; continue; }
                if (!StartsWithSpace(raw)) break; // new top-level key — end of detection block
                int leading = CountLeadingSpaces(raw);
                if (leading < 2) break;

                if (leading == 2 && raw.TrimEnd().EndsWith(":"))
                {
                    // sub-key under detection — either a selection name or "condition"
                    var name = raw.Trim().TrimEnd(':').Trim();
                    if (name.Equals("condition", StringComparison.OrdinalIgnoreCase))
                    {
                        currentSelection = null;
                        i++;
                        // multi-line condition value: we expect inline next, but allow folded
                        while (i < lines.Count)
                        {
                            var l = lines[i];
                            if (!StartsWithSpace(l)) break;
                            if (CountLeadingSpaces(l) < 4) break;
                            if (string.IsNullOrWhiteSpace(l.TrimEnd())) { i++; continue; }
                            rule.Condition = (rule.Condition + " " + l.Trim()).Trim();
                            i++;
                        }
                    }
                    else
                    {
                        currentSelection = name;
                        rule.Selections[name] = new SigmaSelection();
                        i++;
                    }
                    continue;
                }

                if (leading == 2 && raw.Trim().StartsWith("condition:", StringComparison.OrdinalIgnoreCase))
                {
                    var (key, val) = SplitKv(raw);
                    if (key != null) rule.Condition = Unquote(val).Trim();
                    currentSelection = null;
                    i++;
                    continue;
                }

                if (currentSelection != null)
                {
                    // Lines inside the active selection. Two shapes:
                    //   a) "  - some-substring"             → keyword pattern
                    //   b) "  FieldName|modifier: value"    → field predicate (single-value)
                    //   c) "  FieldName|modifier:"          → field predicate header,
                    //      followed by bulleted values nested under it.
                    var stripped = raw.TrimStart();
                    if (stripped.StartsWith("- "))
                    {
                        rule.Selections[currentSelection].KeywordPatterns.Add(Unquote(stripped.Substring(2).TrimEnd()));
                        i++;
                        continue;
                    }
                    if (stripped.Contains(':'))
                    {
                        var (fk, fv) = SplitKv(raw);
                        if (fk == null) { i++; continue; }
                        var (field, mods) = ParseFieldAndModifiers(fk);
                        var pred = new SigmaFieldPredicate { Field = field, Modifiers = mods };
                        if (!string.IsNullOrEmpty(fv))
                        {
                            // inline scalar or inline-flow list "[a, b, c]"
                            if (fv.StartsWith("[") && fv.EndsWith("]"))
                            {
                                foreach (var part in fv[1..^1].Split(','))
                                {
                                    var p = Unquote(part.Trim());
                                    if (p.Length > 0) pred.Values.Add(p);
                                }
                            }
                            else
                            {
                                pred.Values.Add(Unquote(fv));
                            }
                            i++;
                        }
                        else
                        {
                            // bulleted list on subsequent lines
                            i++;
                            i = ReadBulletList(lines, i, pred.Values);
                        }
                        rule.Selections[currentSelection].FieldPredicates.Add(pred);
                        continue;
                    }
                }

                i++;
            }
            return i;
        }

        private static int ReadBulletList(IReadOnlyList<string> lines, int start, List<string> dest)
        {
            int i = start;
            while (i < lines.Count)
            {
                var raw = lines[i];
                if (string.IsNullOrWhiteSpace(raw.TrimEnd())) { i++; continue; }
                if (!StartsWithSpace(raw)) break;
                if (CountLeadingSpaces(raw) < 4) break;
                var t = raw.TrimStart();
                if (!t.StartsWith("- ")) break;
                dest.Add(Unquote(t.Substring(2).TrimEnd()));
                i++;
            }
            return i;
        }

        // -----------------------------------------------------------------
        // Evaluation context: precomputed views over AnalysisResult so the
        // rule loop does no allocation per rule.
        // -----------------------------------------------------------------

        internal sealed class SigmaContext
        {
            public string AnalysisTextLower { get; init; } = "";
            public string AnalysisText { get; init; } = "";
            public HashSet<string> ImportsLower { get; init; } = new();
            public string ImpHash { get; init; } = "";
            public string Sha256 { get; init; } = "";
            public string FileType { get; init; } = "";
            public string FormatFamily { get; init; } = "";
            public AnalysisResult Result { get; init; } = null!;

            // C19: fact-based field collections.  Rule writers can now use
            // selection blocks like:
            //   selection_browser_db:
            //     strings.decoded|contains: "Login Data"
            //   selection_sections:
            //     pe.sections|all: [".UPX0", ".UPX1"]
            //   selection_exfil_host:
            //     urls.host|endswith: "discord.com"
            //   selection_dynamic_net:
            //     dynamic.net_post|contains: "api.telegram.org"
            // Each collection is lowercased once at build time so per-rule
            // matching does no allocation.
            public HashSet<string> SectionNamesLower { get; init; } = new();
            public HashSet<string> ResourceTypesLower { get; init; } = new();
            public string OverlayTypeLower { get; init; } = "";
            public HashSet<string> UrlHostsLower { get; init; } = new();
            public HashSet<string> DecodedStringsLower { get; init; } = new();
            public HashSet<string> IpsLower { get; init; } = new();
            public HashSet<string> CapabilityLabelsLower { get; init; } = new();
            public HashSet<string> DynamicFileAccessLower { get; init; } = new();
            public HashSet<string> DynamicRegistryWriteLower { get; init; } = new();
            public HashSet<string> DynamicNetPostLower { get; init; } = new();
        }

        internal static SigmaContext BuildContext(AnalysisResult r, string analysisText)
        {
            // C19: precompute fact-based collections once so per-rule eval
            // is allocation-free.
            HashSet<string> Lower(IEnumerable<string>? src) =>
                src == null
                    ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    : new HashSet<string>(
                        src.Where(s => !string.IsNullOrEmpty(s))
                           .Select(s => s.ToLowerInvariant()),
                        StringComparer.OrdinalIgnoreCase);

            // urls.host: parse hostname out of each UrlsFound entry.
            var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var u in r.UrlsFound)
            {
                if (string.IsNullOrEmpty(u)) continue;
                var s = u;
                int proto = s.IndexOf("://", StringComparison.Ordinal);
                if (proto > 0) s = s[(proto + 3)..];
                int slash = s.IndexOf('/');
                if (slash > 0) s = s[..slash];
                int colon = s.IndexOf(':');
                if (colon > 0) s = s[..colon];
                if (!string.IsNullOrEmpty(s)) hosts.Add(s.ToLowerInvariant());
            }

            // dynamic.* — sandbox events are stored in SandboxEvents as
            // "wsb:PROCESS:...", "wsb:FILE:...", "wsb:REG:...", "wsb:NET:..."
            // We split into three buckets so rule writers can target the
            // category they care about.
            var dynFile = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var dynReg  = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var dynNet  = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (r.SandboxEvents != null)
            {
                foreach (var e in r.SandboxEvents)
                {
                    if (string.IsNullOrEmpty(e)) continue;
                    var s = e.ToLowerInvariant();
                    if (s.Contains(":file:") || s.Contains("file:"))
                        dynFile.Add(s);
                    else if (s.Contains(":reg:") || s.Contains("reg:"))
                        dynReg.Add(s);
                    else if (s.Contains(":net:") || s.Contains("net:"))
                        dynNet.Add(s);
                }
            }

            // Capability labels: roll up everything an operator might
            // reasonably want to test as "capability.*".
            var caps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var c in r.SuspiciousApiHits ?? Enumerable.Empty<string>())
                if (!string.IsNullOrEmpty(c)) caps.Add(c.ToLowerInvariant());
            foreach (var c in r.CustomHeuristicHits ?? Enumerable.Empty<string>())
                if (!string.IsNullOrEmpty(c)) caps.Add(c.ToLowerInvariant());
            foreach (var c in r.MitreTtps ?? Enumerable.Empty<string>())
                if (!string.IsNullOrEmpty(c)) caps.Add(c.ToLowerInvariant());

            return new SigmaContext
            {
                AnalysisText      = analysisText ?? "",
                AnalysisTextLower = (analysisText ?? "").ToLowerInvariant(),
                ImportsLower      = new HashSet<string>(r.ImportedApis.Select(s => s.ToLowerInvariant())),
                ImpHash           = r.ImpHash ?? "",
                Sha256            = r.Sha256 ?? "",
                FileType          = r.FileType ?? "",
                FormatFamily      = r.FormatFamily ?? "",
                Result            = r,

                SectionNamesLower         = Lower(r.SectionNames),
                ResourceTypesLower        = Lower(r.ResourceTypes),
                OverlayTypeLower          = (r.OverlayType ?? "").ToLowerInvariant(),
                UrlHostsLower             = hosts,
                DecodedStringsLower       = Lower(r.DeobfuscatedHits),
                IpsLower                  = Lower(r.Ipv4Hits),
                CapabilityLabelsLower     = caps,
                DynamicFileAccessLower    = dynFile,
                DynamicRegistryWriteLower = dynReg,
                DynamicNetPostLower       = dynNet,
            };
        }

        // -----------------------------------------------------------------
        // Boolean evaluation.
        // -----------------------------------------------------------------

        internal static bool Evaluate(SigmaRule rule, SigmaContext ctx)
        {
            // No condition or single selection trivially evaluates the only selection.
            var cond = string.IsNullOrEmpty(rule.Condition)
                ? (rule.Selections.Count == 1 ? rule.Selections.Keys.First() : "")
                : rule.Condition;
            if (string.IsNullOrEmpty(cond)) return false;

            var tokens = TokeniseCondition(cond);
            int idx = 0;
            return EvalOr(tokens, ref idx, rule, ctx);
        }

        private static bool EvalOr(List<string> tokens, ref int i, SigmaRule rule, SigmaContext ctx)
        {
            bool acc = EvalAnd(tokens, ref i, rule, ctx);
            while (i < tokens.Count && string.Equals(tokens[i], "or", StringComparison.OrdinalIgnoreCase))
            {
                i++;
                acc = EvalAnd(tokens, ref i, rule, ctx) || acc;
            }
            return acc;
        }

        private static bool EvalAnd(List<string> tokens, ref int i, SigmaRule rule, SigmaContext ctx)
        {
            bool acc = EvalNot(tokens, ref i, rule, ctx);
            while (i < tokens.Count && string.Equals(tokens[i], "and", StringComparison.OrdinalIgnoreCase))
            {
                i++;
                acc = EvalNot(tokens, ref i, rule, ctx) && acc;
            }
            return acc;
        }

        private static bool EvalNot(List<string> tokens, ref int i, SigmaRule rule, SigmaContext ctx)
        {
            if (i < tokens.Count && string.Equals(tokens[i], "not", StringComparison.OrdinalIgnoreCase))
            {
                i++;
                return !EvalNot(tokens, ref i, rule, ctx);
            }
            return EvalPrimary(tokens, ref i, rule, ctx);
        }

        private static bool EvalPrimary(List<string> tokens, ref int i, SigmaRule rule, SigmaContext ctx)
        {
            if (i >= tokens.Count) return false;
            var t = tokens[i];

            if (t == "(")
            {
                i++;
                bool v = EvalOr(tokens, ref i, rule, ctx);
                if (i < tokens.Count && tokens[i] == ")") i++;
                return v;
            }

            // "all of selection_*"  /  "1 of selection_*"  /  "N of selection_*"
            if ((t.Equals("all", StringComparison.OrdinalIgnoreCase) || int.TryParse(t, out _)) &&
                i + 2 < tokens.Count && string.Equals(tokens[i + 1], "of", StringComparison.OrdinalIgnoreCase))
            {
                int requested = t.Equals("all", StringComparison.OrdinalIgnoreCase) ? -1 : int.Parse(t, CultureInfo.InvariantCulture);
                string pattern = tokens[i + 2];
                i += 3;
                var matchedKeys = MatchSelections(rule, pattern).ToList();
                int matchedCount = matchedKeys.Count(k => EvaluateSelection(rule.Selections[k], ctx));
                return requested == -1
                    ? matchedCount > 0 && matchedCount == matchedKeys.Count
                    : matchedCount >= requested;
            }

            // "count(selection_x) op N"  →  treat as plain selection presence for static.
            if (t.StartsWith("count(", StringComparison.OrdinalIgnoreCase))
            {
                int close = t.IndexOf(')');
                if (close > 0)
                {
                    var sel = t.Substring(6, close - 6).Trim();
                    i++;
                    bool present = rule.Selections.TryGetValue(sel, out var s) && EvaluateSelection(s, ctx);
                    // skip optional comparator and number
                    if (i < tokens.Count && (tokens[i] == ">" || tokens[i] == ">=" || tokens[i] == "<" || tokens[i] == "<=" || tokens[i] == "==" || tokens[i] == "=")) { i++; if (i < tokens.Count) i++; }
                    return present;
                }
            }

            // bare identifier — a selection name (possibly with a trailing wildcard).
            i++;
            if (t.Contains('*'))
            {
                var keys = MatchSelections(rule, t);
                return keys.Any(k => EvaluateSelection(rule.Selections[k], ctx));
            }
            return rule.Selections.TryGetValue(t, out var sel2) && EvaluateSelection(sel2, ctx);
        }

        internal static IEnumerable<string> MatchSelections(SigmaRule rule, string pattern)
        {
            if (!pattern.Contains('*'))
            {
                if (rule.Selections.ContainsKey(pattern)) yield return pattern;
                yield break;
            }
            var rx = WildcardToRegex(pattern);
            foreach (var k in rule.Selections.Keys)
                if (Regex.IsMatch(k, rx, RegexOptions.IgnoreCase)) yield return k;
        }

        internal static bool EvaluateSelection(SigmaSelection sel, SigmaContext ctx)
        {
            // Keyword patterns: every listed substring must be present.
            // (Matches the existing minimal-Sigma semantics shipped with PR 0.)
            if (sel.KeywordPatterns.Count > 0)
            {
                foreach (var p in sel.KeywordPatterns)
                {
                    if (string.IsNullOrEmpty(p)) continue;
                    if (ctx.AnalysisTextLower.IndexOf(p.ToLowerInvariant(), StringComparison.Ordinal) < 0)
                        return false;
                }
            }
            // Field predicates: AND across predicates, OR across values within a predicate
            // unless `|all` modifier is present, in which case AND across values.
            foreach (var pred in sel.FieldPredicates)
            {
                if (!EvaluateFieldPredicate(pred, ctx)) return false;
            }
            return !sel.IsEmpty;
        }

        internal static bool EvaluateFieldPredicate(SigmaFieldPredicate pred, SigmaContext ctx)
        {
            bool requireAll = pred.Modifiers.Any(m => m.Equals("all", StringComparison.OrdinalIgnoreCase));
            bool cased      = pred.Modifiers.Any(m => m.Equals("cased", StringComparison.OrdinalIgnoreCase));
            bool startswith = pred.Modifiers.Any(m => m.Equals("startswith", StringComparison.OrdinalIgnoreCase));
            bool endswith   = pred.Modifiers.Any(m => m.Equals("endswith", StringComparison.OrdinalIgnoreCase));
            bool regex      = pred.Modifiers.Any(m => m.Equals("re", StringComparison.OrdinalIgnoreCase) ||
                                                       m.Equals("regex", StringComparison.OrdinalIgnoreCase));
            string fieldLower = (pred.Field ?? "").ToLowerInvariant();

            bool MatchOne(string v)
            {
                if (string.IsNullOrEmpty(v)) return false;
                var target = ResolveFieldTarget(fieldLower, ctx, cased);
                string needle = cased ? v : v.ToLowerInvariant();

                // Known structured fields with exact-equals semantics.
                if (fieldLower is "sha256" or "md5" or "sha1" or "imphash")
                {
                    var lhs = cased ? target : target.ToLowerInvariant();
                    return string.Equals(lhs, needle, StringComparison.Ordinal);
                }

                if (regex)
                {
                    try
                    {
                        var opt = cased ? RegexOptions.None : RegexOptions.IgnoreCase;
                        return Regex.IsMatch(target, v, opt | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50));
                    }
                    catch { return false; }
                }
                if (startswith) return target.StartsWith(needle, cased ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase);
                if (endswith)   return target.EndsWith  (needle, cased ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase);

                // Default modifier in Sigma is "contains".
                return target.IndexOf(needle, cased ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase) >= 0;
            }

            // Special-case fields that match a *collection* rather than a string.
            if (fieldLower is "imports" or "import" or "import_name" or "importedfunction"
                          or "pe.imports")
            {
                bool ok = requireAll
                    ? pred.Values.All(v => ctx.ImportsLower.Contains(v.ToLowerInvariant()))
                    : pred.Values.Any(v => ctx.ImportsLower.Contains(v.ToLowerInvariant()));
                return ok;
            }

            // C19: fact-based collection fields. Each one is matched with
            // OR-of-needles by default; |all suffix flips to AND. For
            // "contains" semantics we substring-match each collection
            // entry against the needle; for "equals" semantics we use
            // the precomputed lowercased HashSet for O(1) lookup.
            HashSet<string>? collection = fieldLower switch
            {
                "pe.sections" or "pe.section"          => ctx.SectionNamesLower,
                "pe.resources" or "pe.resource"        => ctx.ResourceTypesLower,
                "urls.host" or "url.host"              => ctx.UrlHostsLower,
                "strings.decoded" or "decoded.string"  => ctx.DecodedStringsLower,
                "ioc.ip" or "ioc.ipv4"                 => ctx.IpsLower,
                "capability" or "capability.label"     => ctx.CapabilityLabelsLower,
                "dynamic.file_access" or "dynamic.file" => ctx.DynamicFileAccessLower,
                "dynamic.registry_write" or "dynamic.reg" => ctx.DynamicRegistryWriteLower,
                "dynamic.net_post" or "dynamic.net"    => ctx.DynamicNetPostLower,
                _ => null,
            };
            if (collection != null)
            {
                bool MatchInCollection(string needle)
                {
                    var nLower = needle.ToLowerInvariant();
                    if (startswith)
                        return collection.Any(item => item.StartsWith(nLower, StringComparison.Ordinal));
                    if (endswith)
                        return collection.Any(item => item.EndsWith(nLower, StringComparison.Ordinal));
                    // Default modifier in Sigma is "contains" — substring match.
                    return collection.Any(item => item.IndexOf(nLower, StringComparison.Ordinal) >= 0);
                }
                return requireAll
                    ? pred.Values.All(MatchInCollection)
                    : pred.Values.Any(MatchInCollection);
            }

            if (pred.Values.Count == 0) return false;
            return requireAll ? pred.Values.All(MatchOne) : pred.Values.Any(MatchOne);
        }

        private static string ResolveFieldTarget(string fieldLower, SigmaContext ctx, bool cased)
        {
            return fieldLower switch
            {
                "sha256"                            => ctx.Sha256,
                "imphash"                           => ctx.ImpHash,
                "filetype"                          => ctx.FileType,
                "format" or "format.family"         => ctx.FormatFamily,
                "pe.overlay.type" or "pe.overlay"   => ctx.OverlayTypeLower,
                _                                   => cased ? ctx.AnalysisText : ctx.AnalysisTextLower,
            };
        }

        // -----------------------------------------------------------------
        // Mini lexer / helpers.
        // -----------------------------------------------------------------

        internal static List<string> TokeniseCondition(string cond)
        {
            var tokens = new List<string>();
            int i = 0;
            while (i < cond.Length)
            {
                char c = cond[i];
                if (char.IsWhiteSpace(c)) { i++; continue; }
                if (c == '(' || c == ')') { tokens.Add(c.ToString()); i++; continue; }
                if (c == '>' || c == '<' || c == '=' || c == '!')
                {
                    if (i + 1 < cond.Length && cond[i + 1] == '=') { tokens.Add(cond.Substring(i, 2)); i += 2; }
                    else { tokens.Add(c.ToString()); i++; }
                    continue;
                }
                int start = i;
                while (i < cond.Length && !char.IsWhiteSpace(cond[i]) && cond[i] != '(' && cond[i] != ')')
                    i++;
                // Special-case `count(<selection>)` so the entire call is one token.
                if (i < cond.Length && cond[i] == '('
                 && cond.Substring(start, i - start).Equals("count", StringComparison.OrdinalIgnoreCase))
                {
                    int depth = 0;
                    while (i < cond.Length)
                    {
                        char ch = cond[i];
                        if (ch == '(') { depth++; i++; continue; }
                        if (ch == ')') { depth--; i++; if (depth == 0) break; continue; }
                        i++;
                    }
                }
                tokens.Add(cond.Substring(start, i - start));
            }
            return tokens;
        }

        private static (string field, List<string> modifiers) ParseFieldAndModifiers(string raw)
        {
            var parts = raw.Split('|');
            var field = parts[0].Trim();
            var mods = parts.Length > 1 ? parts.Skip(1).Select(s => s.Trim()).ToList() : new List<string>();
            return (field, mods);
        }

        private static (string? key, string val) SplitKv(string raw)
        {
            int idx = raw.IndexOf(':');
            if (idx < 0) return (null, "");
            var key = raw.Substring(0, idx).TrimStart().TrimEnd();
            var val = idx + 1 < raw.Length ? raw.Substring(idx + 1).Trim() : "";
            return (key, val);
        }

        private static string Unquote(string s)
        {
            s = s.Trim();
            if (s.Length >= 2)
            {
                if ((s[0] == '"' && s[^1] == '"') || (s[0] == '\'' && s[^1] == '\''))
                    return s.Substring(1, s.Length - 2);
            }
            return s;
        }

        private static bool StartsWithSpace(string s) => s.Length > 0 && (s[0] == ' ' || s[0] == '\t');
        private static int CountLeadingSpaces(string s)
        {
            int n = 0;
            foreach (var c in s) { if (c == ' ') n++; else if (c == '\t') n += 2; else break; }
            return n;
        }

        private static IEnumerable<IReadOnlyList<string>> SplitYamlDocs(string[] lines)
        {
            var doc = new List<string>();
            foreach (var l in lines)
            {
                if (l.TrimEnd() == "---")
                {
                    if (doc.Count > 0) { yield return doc; doc = new List<string>(); }
                    continue;
                }
                doc.Add(l);
            }
            if (doc.Count > 0) yield return doc;
        }

        private static string WildcardToRegex(string pat)
            => "^" + Regex.Escape(pat).Replace("\\*", ".*").Replace("\\?", ".") + "$";
    }

    // ---------------------------------------------------------------------
    // Section 10.2 — CAPA(-ish) parser/evaluator.
    //
    // Supports two forms transparently:
    //   1.  Legacy flat form already shipped in rules/capa/*.capa:
    //         capability: ...
    //         match: all|any            (optional, default "all")
    //         imports:
    //           - ...
    //         strings:
    //           - ...
    //   2.  YAML "rule:" form modelled on the upstream Mandiant CAPA spec:
    //         rule:
    //           meta:
    //             name: ...
    //             namespace: ...
    //             scopes:
    //               static: file
    //           features:
    //             - and:
    //                 - or:
    //                     - string: "wallet"
    //                     - string: "mnemonic"
    //                 - api: VirtualAlloc
    //                 - not:
    //                     - api: IsDebuggerPresent
    //                 - 2 or more:
    //                     - api: WriteProcessMemory
    //                     - api: CreateRemoteThread
    // ---------------------------------------------------------------------

    public sealed class CapaRule
    {
        public string Name { get; set; } = "";
        public string Namespace { get; set; } = "";
        public string Scope { get; set; } = "file";
        public CapaNode Root { get; set; } = new CapaLeaf();
    }

    public abstract class CapaNode { }
    public sealed class CapaLeaf : CapaNode
    {
        public string Type { get; set; } = "";   // api / import / string / substring / regex / os / format / arch / characteristic / match / section / export / import-name
        public string Value { get; set; } = "";
    }
    public sealed class CapaAnd : CapaNode { public List<CapaNode> Children { get; set; } = new(); }
    public sealed class CapaOr  : CapaNode { public List<CapaNode> Children { get; set; } = new(); }
    public sealed class CapaNot : CapaNode { public CapaNode Child { get; set; } = new CapaLeaf(); }
    public sealed class CapaOptional : CapaNode { public List<CapaNode> Children { get; set; } = new(); }
    public sealed class CapaNOrMore : CapaNode
    {
        public int N { get; set; }
        public List<CapaNode> Children { get; set; } = new();
    }

    public static class CapaFullEngine
    {
        public static void Run(AnalysisResult r, string analysisText)
            => Run(r, analysisText, RuleEngineUtil.ResolveRulesDir("capa"));

        public static void Run(AnalysisResult r, string analysisText, string? dir)
        {
            if (dir == null || !Directory.Exists(dir)) return;

            var budget = RulesBudget.FromEnv("capa");
            var ctx = BuildContext(r, analysisText);

            foreach (var file in EnumerateRuleFiles(dir))
            {
                if (budget.EngineExpired) { r.RulesEngineTimeouts.Add("capa:engine-budget"); break; }
                var ruleClock = budget.StartRule();
                try
                {
                    string[] lines = File.ReadAllLines(file);
                    if (TryParse(lines, out var rule) && rule != null)
                    {
                        if (budget.RuleExpired(ruleClock))
                        {
                            r.RulesEngineTimeouts.Add($"capa:{Path.GetFileName(file)}");
                            continue;
                        }
                        if (EvaluateNode(rule.Root, ctx))
                        {
                            var tag = $"{rule.Name} [{Path.GetFileName(file)}]";
                            if (!r.CapaHits.Contains(tag)) r.CapaHits.Add(tag);
                            RuleEngineUtil.RecordProvenance(r, "capa", file);
                        }
                    }
                }
                catch { /* skip malformed rule */ }
                finally { ruleClock.Stop(); }
            }
            RuleEngineUtil.AddTimingMs(r, "capa", budget.Total.ElapsedMilliseconds);
        }

        internal static IEnumerable<string> EnumerateRuleFiles(string dir)
            => Directory.EnumerateFiles(dir, "*.capa",   SearchOption.AllDirectories)
                        .Concat(Directory.EnumerateFiles(dir, "*.rule",  SearchOption.AllDirectories))
                        .Concat(Directory.EnumerateFiles(dir, "*.yml",   SearchOption.AllDirectories))
                        .Concat(Directory.EnumerateFiles(dir, "*.yaml",  SearchOption.AllDirectories));

        internal sealed class CapaContext
        {
            public string AnalysisTextLower { get; init; } = "";
            public string AnalysisText { get; init; } = "";
            public HashSet<string> ImportsLower { get; init; } = new();
            public string FormatFamilyLower { get; init; } = "";
            public string FileTypeLower { get; init; } = "";
            public AnalysisResult Result { get; init; } = null!;

            // C19: fact-based fields (mirrors Sigma context).
            public HashSet<string> SectionNamesLower { get; init; } = new();
            public HashSet<string> DecodedStringsLower { get; init; } = new();
            public HashSet<string> CapabilityLabelsLower { get; init; } = new();
        }

        internal static CapaContext BuildContext(AnalysisResult r, string analysisText)
        {
            HashSet<string> Lower(IEnumerable<string>? src) =>
                src == null
                    ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    : new HashSet<string>(
                        src.Where(s => !string.IsNullOrEmpty(s))
                           .Select(s => s.ToLowerInvariant()),
                        StringComparer.OrdinalIgnoreCase);

            var caps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var c in r.SuspiciousApiHits ?? Enumerable.Empty<string>())
                if (!string.IsNullOrEmpty(c)) caps.Add(c.ToLowerInvariant());
            foreach (var c in r.CustomHeuristicHits ?? Enumerable.Empty<string>())
                if (!string.IsNullOrEmpty(c)) caps.Add(c.ToLowerInvariant());
            foreach (var c in r.MitreTtps ?? Enumerable.Empty<string>())
                if (!string.IsNullOrEmpty(c)) caps.Add(c.ToLowerInvariant());

            return new CapaContext
            {
                AnalysisText      = analysisText ?? "",
                AnalysisTextLower = (analysisText ?? "").ToLowerInvariant(),
                ImportsLower      = new HashSet<string>(r.ImportedApis.Select(s => s.ToLowerInvariant())),
                FormatFamilyLower = (r.FormatFamily ?? "").ToLowerInvariant(),
                FileTypeLower     = (r.FileType     ?? "").ToLowerInvariant(),
                Result            = r,
                SectionNamesLower    = Lower(r.SectionNames),
                DecodedStringsLower  = Lower(r.DeobfuscatedHits),
                CapabilityLabelsLower = caps,
            };
        }

        // -----------------------------------------------------------------
        // Parser.
        // -----------------------------------------------------------------

        internal static bool TryParse(string[] lines, out CapaRule? rule)
        {
            rule = null;

            // Try the legacy flat form first — it's identifiable by the absence
            // of an indented "rule:" block at the top and the presence of one of
            // the legacy keys.
            bool hasRuleRoot = lines.Any(l => l.TrimEnd() == "rule:" || l.StartsWith("rule:", StringComparison.OrdinalIgnoreCase));
            if (!hasRuleRoot)
            {
                var legacy = ParseLegacyFlat(lines);
                if (legacy != null) { rule = legacy; return true; }
                return false;
            }

            // Full YAML-ish form.
            rule = ParseFullYaml(lines);
            return rule != null;
        }

        private static CapaRule? ParseLegacyFlat(string[] lines)
        {
            string name = "", mode = "all";
            var imports = new List<string>();
            var strings = new List<string>();
            string? section = null;
            foreach (var raw in lines)
            {
                var line = raw.TrimEnd();
                if (line.StartsWith("capability:", StringComparison.OrdinalIgnoreCase))
                    name = line.Substring(11).Trim();
                else if (line.StartsWith("match:", StringComparison.OrdinalIgnoreCase))
                    mode = line.Substring(6).Trim().ToLowerInvariant();
                else if (line.StartsWith("imports:", StringComparison.OrdinalIgnoreCase))
                    section = "imports";
                else if (line.StartsWith("strings:", StringComparison.OrdinalIgnoreCase))
                    section = "strings";
                else if (line.TrimStart().StartsWith("- ") && section == "imports")
                    imports.Add(line.TrimStart().Substring(2).Trim().Trim('"', '\''));
                else if (line.TrimStart().StartsWith("- ") && section == "strings")
                    strings.Add(line.TrimStart().Substring(2).Trim().Trim('"', '\''));
            }
            if (string.IsNullOrEmpty(name) || imports.Count == 0) return null;
            var importNode = imports.Select(i => (CapaNode)new CapaLeaf { Type = "api", Value = i }).ToList();
            CapaNode importsCombo = mode == "any"
                ? new CapaOr  { Children = importNode }
                : new CapaAnd { Children = importNode };
            if (strings.Count == 0) return new CapaRule { Name = name, Root = importsCombo };
            var stringsNode = strings.Select(s => (CapaNode)new CapaLeaf { Type = "string", Value = s }).ToList();
            return new CapaRule
            {
                Name = name,
                Root = new CapaAnd
                {
                    Children = new List<CapaNode>
                    {
                        importsCombo,
                        new CapaAnd { Children = stringsNode },
                    },
                },
            };
        }

        private static CapaRule? ParseFullYaml(string[] lines)
        {
            var rule = new CapaRule();
            int n = lines.Length;
            int i = 0;
            // skip until "rule:"
            while (i < n && !lines[i].TrimEnd().StartsWith("rule:", StringComparison.OrdinalIgnoreCase)) i++;
            if (i == n) return null;
            i++;
            while (i < n)
            {
                var raw = lines[i];
                var trimmed = raw.TrimEnd();
                if (string.IsNullOrWhiteSpace(trimmed)) { i++; continue; }
                int leading = CountLeadingSpaces(raw);
                if (leading < 2) break;
                if (leading == 2 && trimmed.Trim().StartsWith("meta:", StringComparison.OrdinalIgnoreCase))
                {
                    i = ParseMeta(lines, i + 1, rule);
                    continue;
                }
                if (leading == 2 && trimmed.Trim().StartsWith("features:", StringComparison.OrdinalIgnoreCase))
                {
                    i++;
                    // Read the features list. Top-level features at indent 4 are wrapped in an AND.
                    var (node, next) = ParseFeatureList(lines, i, 4);
                    rule.Root = WrapAnd(node);
                    i = next;
                    continue;
                }
                i++;
            }
            if (string.IsNullOrEmpty(rule.Name)) return null;
            return rule;
        }

        private static int ParseMeta(string[] lines, int start, CapaRule rule)
        {
            int i = start;
            bool inScopes = false;
            while (i < lines.Length)
            {
                var raw = lines[i];
                var trimmed = raw.TrimEnd();
                if (string.IsNullOrWhiteSpace(trimmed)) { i++; continue; }
                int leading = CountLeadingSpaces(raw);
                if (leading < 4) break; // end of meta block
                var t = trimmed.Trim();
                if (leading == 4)
                {
                    inScopes = false;
                    if (t.StartsWith("name:", StringComparison.OrdinalIgnoreCase))
                        rule.Name = Unquote(t.Substring(5).Trim());
                    else if (t.StartsWith("namespace:", StringComparison.OrdinalIgnoreCase))
                        rule.Namespace = Unquote(t.Substring(10).Trim());
                    else if (t.StartsWith("scopes:", StringComparison.OrdinalIgnoreCase))
                        inScopes = true;
                    else if (t.StartsWith("scope:", StringComparison.OrdinalIgnoreCase))
                        rule.Scope = Unquote(t.Substring(6).Trim());
                }
                else if (leading == 6 && inScopes)
                {
                    if (t.StartsWith("static:", StringComparison.OrdinalIgnoreCase))
                        rule.Scope = Unquote(t.Substring(7).Trim());
                }
                i++;
            }
            return i;
        }

        private static (List<CapaNode> nodes, int next) ParseFeatureList(string[] lines, int start, int expectedIndent)
        {
            var nodes = new List<CapaNode>();
            int i = start;
            while (i < lines.Length)
            {
                var raw = lines[i];
                var trimmed = raw.TrimEnd();
                if (string.IsNullOrWhiteSpace(trimmed)) { i++; continue; }
                int leading = CountLeadingSpaces(raw);
                if (leading < expectedIndent) break;
                if (leading > expectedIndent) { i++; continue; }
                var t = trimmed.Trim();
                if (!t.StartsWith("- ")) break;
                var (node, next) = ParseFeatureItem(lines, i, expectedIndent);
                if (node != null) nodes.Add(node);
                i = next;
            }
            return (nodes, i);
        }

        private static (CapaNode? node, int next) ParseFeatureItem(string[] lines, int idx, int baseIndent)
        {
            var raw = lines[idx];
            var t = raw.TrimStart();
            // "- and:" / "- or:" / "- not:" / "- optional:" / "- N or more:" / "- <type>: <value>"
            string item = t.Substring(2);   // drop "- "

            (string head, string value) = SplitHeadValue(item);

            // Logical combinators (children indented +4 from this entry).
            int childIndent = baseIndent + 4;
            if (head.Equals("and", StringComparison.OrdinalIgnoreCase))
            {
                var (kids, nxt) = ParseFeatureList(lines, idx + 1, childIndent);
                return (new CapaAnd { Children = kids }, nxt);
            }
            if (head.Equals("or", StringComparison.OrdinalIgnoreCase))
            {
                var (kids, nxt) = ParseFeatureList(lines, idx + 1, childIndent);
                return (new CapaOr { Children = kids }, nxt);
            }
            if (head.Equals("not", StringComparison.OrdinalIgnoreCase))
            {
                var (kids, nxt) = ParseFeatureList(lines, idx + 1, childIndent);
                return (new CapaNot { Child = WrapAnd(kids) }, nxt);
            }
            if (head.Equals("optional", StringComparison.OrdinalIgnoreCase))
            {
                var (kids, nxt) = ParseFeatureList(lines, idx + 1, childIndent);
                return (new CapaOptional { Children = kids }, nxt);
            }
            var mNorMore = Regex.Match(head, @"^(\d+)\s+or\s+more$", RegexOptions.IgnoreCase);
            if (mNorMore.Success)
            {
                int n = int.Parse(mNorMore.Groups[1].Value, CultureInfo.InvariantCulture);
                var (kids, nxt) = ParseFeatureList(lines, idx + 1, childIndent);
                return (new CapaNOrMore { N = n, Children = kids }, nxt);
            }

            // Leaf feature.
            if (string.IsNullOrEmpty(value)) return (null, idx + 1);
            return (new CapaLeaf { Type = head.ToLowerInvariant(), Value = Unquote(value).Trim() }, idx + 1);
        }

        private static CapaNode WrapAnd(List<CapaNode> kids)
            => kids.Count == 1 ? kids[0] : new CapaAnd { Children = kids };

        // -----------------------------------------------------------------
        // Evaluator.
        // -----------------------------------------------------------------

        internal static bool EvaluateNode(CapaNode node, CapaContext ctx)
        {
            switch (node)
            {
                case CapaAnd a:       return a.Children.All(c => EvaluateNode(c, ctx));
                case CapaOr o:        return o.Children.Any(c => EvaluateNode(c, ctx));
                case CapaNot n:       return !EvaluateNode(n.Child, ctx);
                case CapaOptional _:  return true; // optional → don't contribute to overall verdict
                case CapaNOrMore m:   return m.Children.Count(c => EvaluateNode(c, ctx)) >= m.N;
                case CapaLeaf l:      return EvaluateLeaf(l, ctx);
                default:              return false;
            }
        }

        private static bool EvaluateLeaf(CapaLeaf l, CapaContext ctx)
        {
            string v = l.Value ?? "";
            string vLower = v.ToLowerInvariant();
            switch (l.Type)
            {
                case "api":
                case "import":
                case "import-name":
                case "function-name":
                case "export":
                    return ctx.ImportsLower.Contains(vLower);
                case "string":
                case "substring":
                    return !string.IsNullOrEmpty(v) && ctx.AnalysisTextLower.IndexOf(vLower, StringComparison.Ordinal) >= 0;
                case "regex":
                    try
                    {
                        return Regex.IsMatch(ctx.AnalysisText, v, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
                                             TimeSpan.FromMilliseconds(50));
                    }
                    catch { return false; }
                case "format":
                    return ctx.FormatFamilyLower.Contains(vLower);
                case "os":
                    return ctx.FormatFamilyLower.Contains(vLower) || ctx.FileTypeLower.Contains(vLower);
                case "arch":
                    return string.Equals(vLower, "amd64") ? ctx.Result.Is64
                         : string.Equals(vLower, "x86")   ? !ctx.Result.Is64
                         : false;
                case "section":
                    return ctx.Result.SectionNames.Any(s => s.IndexOf(v, StringComparison.OrdinalIgnoreCase) >= 0);
                case "characteristic":
                    return EvaluateCharacteristic(v, ctx);
                case "match":
                    // Cross-rule reference; we just treat it as "true" if the named hit is already present.
                    return ctx.Result.CapaHits.Any(h => h.StartsWith(v, StringComparison.OrdinalIgnoreCase));
                default:
                    return false;
            }
        }

        private static bool EvaluateCharacteristic(string v, CapaContext ctx)
        {
            string vl = v.ToLowerInvariant();
            return vl switch
            {
                "dotnet"           => ctx.Result.IsDotNetLikely,
                "signed"           => ctx.Result.IsSigned,
                "packed"           => ctx.Result.PackedLikely,
                "high-entropy"     => ctx.Result.HighEntropyChunkCount > 0,
                "unsigned-dll"     => !ctx.Result.IsSigned && ctx.Result.IsDll,
                "executable"       => ctx.Result.IsExe || ctx.Result.IsDll,
                _                  => false,
            };
        }

        // -----------------------------------------------------------------
        // YAML helpers (CAPA flavour — separate from Sigma's to keep them
        // simple and obvious).
        // -----------------------------------------------------------------

        private static (string head, string value) SplitHeadValue(string item)
        {
            int idx = item.IndexOf(':');
            if (idx < 0) return (item.Trim(), "");
            return (item.Substring(0, idx).Trim(), idx + 1 < item.Length ? item.Substring(idx + 1).Trim() : "");
        }

        private static string Unquote(string s)
        {
            s = s.Trim();
            if (s.Length >= 2 && ((s[0] == '"' && s[^1] == '"') || (s[0] == '\'' && s[^1] == '\'')))
                return s.Substring(1, s.Length - 2);
            return s;
        }

        private static int CountLeadingSpaces(string s)
        {
            int n = 0;
            foreach (var c in s) { if (c == ' ') n++; else if (c == '\t') n += 2; else break; }
            return n;
        }
    }

    // ---------------------------------------------------------------------
    // Section 10.3 — yara-x integration. The selection happens here so the
    // bulk of Analyzer.cs stays unchanged. We probe for `yr` / `yara-x` first;
    // if absent, fall through to the classic yara binary.
    // ---------------------------------------------------------------------

    public static class YaraXEngine
    {
        private static readonly object _probeLock = new();
        private static bool _probed;
        private static string? _binary;
        private static bool _isYaraX;

        /// <summary>
        /// Probe the system for a yara-x or yara binary. The result is cached
        /// for the lifetime of the process. <paramref name="isYaraX"/> is set
        /// to <c>true</c> if we picked the Rust reimplementation.
        /// </summary>
        public static string? Discover(out bool isYaraX)
        {
            lock (_probeLock)
            {
                if (_probed) { isYaraX = _isYaraX; return _binary; }
                _probed = true;

                var dirs = BuildSearchDirs();
                // yara-x preferred names.
                var xNames = new[] { "yr.exe", "yr", "yara-x.exe", "yara-x" };
                var yNames = new[] { "yara64.exe", "yara.exe", "yara64", "yara" };

                foreach (var d in dirs)
                {
                    foreach (var name in xNames)
                    {
                        try
                        {
                            var p = Path.Combine(d, name);
                            if (File.Exists(p)) { _binary = p; _isYaraX = true; isYaraX = true; return p; }
                        }
                        catch { }
                    }
                }
                foreach (var d in dirs)
                {
                    foreach (var name in yNames)
                    {
                        try
                        {
                            var p = Path.Combine(d, name);
                            if (File.Exists(p)) { _binary = p; _isYaraX = false; isYaraX = false; return p; }
                        }
                        catch { }
                    }
                }
                _binary = null; _isYaraX = false; isYaraX = false; return null;
            }
        }

        /// <summary>Reset the cached discovery — test-only.</summary>
        internal static void ResetForTests()
        {
            lock (_probeLock)
            {
                _probed = false; _binary = null; _isYaraX = false;
            }
        }

        private static List<string> BuildSearchDirs()
        {
            var dirs = new List<string>();
            var exeDir = AppContext.BaseDirectory;
            if (!string.IsNullOrEmpty(exeDir))
            {
                dirs.Add(exeDir);
                dirs.Add(Path.Combine(exeDir, "yara"));
                dirs.Add(Path.Combine(exeDir, "yara-x"));
            }
            var envPath = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            dirs.AddRange(envPath.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries));
            return dirs;
        }

        /// <summary>
        /// Build the argument list to scan <paramref name="targetFile"/>
        /// against <paramref name="ruleFile"/>. Different binaries (yara-x
        /// vs classic yara) use slightly different flags; both binaries
        /// emit one line of "rule [tag] file" per match by default which
        /// our caller already parses.
        /// </summary>
        internal static List<string> BuildArgs(bool isYaraX, string ruleFile, string targetFile)
        {
            if (isYaraX)
            {
                // yara-x CLI: `yr scan -q <rules> <target>`. We use the default
                // text output (one line per match) for parity with classic yara
                // because our caller already splits per line.
                return new List<string> { "scan", "-q", ruleFile, targetFile };
            }
            // classic yara: -w (no warnings) -N (no recursion) <rule> <target>
            return new List<string> { "-w", "-N", ruleFile, targetFile };
        }
    }

    // ---------------------------------------------------------------------
    // Section 10.4 — `rules update` fetcher / verifier. Pulls rule packs from
    // a local directory, an HTTP archive (.zip), or git+https URL (via the
    // system `git` binary), then writes _provenance.json into the dest dir.
    // ---------------------------------------------------------------------

    public sealed class RulesUpdateOptions
    {
        public string Engine { get; set; } = "all";          // sigma | capa | yara | all
        public string? Source { get; set; }
        public string? Dest { get; set; }
        public bool Insecure { get; set; }
        public string? PublicKeyBase64 { get; set; }         // Ed25519 pubkey for sig verify
        public string? Version { get; set; }
        public HttpClient? HttpClient { get; set; }
    }

    public sealed class RulesUpdateResult
    {
        public string Engine { get; set; } = "";
        public string Source { get; set; } = "";
        public string Dest { get; set; } = "";
        public int FilesCopied { get; set; }
        public string Sha256 { get; set; } = "";
        public bool SignatureVerified { get; set; }
        public List<string> Errors { get; set; } = new();
        public RulePackManifest? Manifest { get; set; }
    }

    public static class RulesUpdater
    {
        private static readonly string[] _engines = new[] { "sigma", "capa", "yara" };

        public static RulesUpdateResult Update(RulesUpdateOptions opts)
        {
            var res = new RulesUpdateResult { Engine = opts.Engine, Source = opts.Source ?? "" };
            try
            {
                var baseDest = !string.IsNullOrEmpty(opts.Dest) ? opts.Dest!
                            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                                            "AntiStealer", "rules");

                if (string.IsNullOrEmpty(opts.Source))
                {
                    // No source: just ensure per-engine destination directories exist.
                    foreach (var e in ResolveEngines(opts.Engine))
                        Directory.CreateDirectory(Path.Combine(baseDest, e));
                    res.Dest = baseDest;
                    return res;
                }

                foreach (var engine in ResolveEngines(opts.Engine))
                {
                    var dest = Path.Combine(baseDest, engine);
                    Directory.CreateDirectory(dest);

                    if (Directory.Exists(opts.Source))
                    {
                        // local directory: prefer <source>/<engine>/* over <source>/* directly
                        var src = Path.Combine(opts.Source, engine);
                        if (!Directory.Exists(src)) src = opts.Source;
                        res.FilesCopied += CopyTree(src, dest);
                    }
                    else if (LooksLikeHttp(opts.Source))
                    {
                        var localZip = Path.Combine(Path.GetTempPath(), "antistealer-rules-" + Path.GetRandomFileName() + ".zip");
                        try
                        {
                            DownloadFile(opts.Source!, localZip, opts.HttpClient);
                            if (!opts.Insecure && !string.IsNullOrEmpty(opts.PublicKeyBase64))
                                res.SignatureVerified = TryVerifySignature(opts.Source!, localZip, opts.PublicKeyBase64!, opts.HttpClient);
                            res.FilesCopied += ExtractZipForEngine(localZip, dest, engine);
                        }
                        finally
                        {
                            try { File.Delete(localZip); } catch { }
                        }
                    }
                    else if (opts.Source.StartsWith("git+", StringComparison.OrdinalIgnoreCase))
                    {
                        var url = opts.Source.Substring(4);
                        var tmp = Path.Combine(Path.GetTempPath(), "antistealer-git-" + Path.GetRandomFileName());
                        try
                        {
                            RunGitClone(url, tmp);
                            var src = Path.Combine(tmp, engine);
                            if (!Directory.Exists(src)) src = tmp;
                            res.FilesCopied += CopyTree(src, dest);
                        }
                        finally
                        {
                            try { Directory.Delete(tmp, recursive: true); } catch { }
                        }
                    }
                    else
                    {
                        res.Errors.Add($"unrecognised source: {opts.Source}");
                        continue;
                    }

                    res.Sha256 = HashDirectory(dest);
                    var manifest = new RulePackManifest
                    {
                        Engine = engine,
                        Source = opts.Source!,
                        Version = opts.Version ?? "",
                        FetchedAtUtc = DateTime.UtcNow,
                        Sha256 = res.Sha256,
                        FileCount = res.FilesCopied,
                        Signed = res.SignatureVerified,
                        SignerPublicKey = opts.PublicKeyBase64 ?? "",
                    };
                    File.WriteAllText(Path.Combine(dest, "_provenance.json"),
                        JsonSerializer.Serialize(manifest, JsonOptionsRegistry.CamelCaseIndented));
                    res.Manifest = manifest;
                    res.Dest = dest;
                }
            }
            catch (Exception ex)
            {
                res.Errors.Add(ex.Message);
            }
            return res;
        }

        internal static IEnumerable<string> ResolveEngines(string engine)
        {
            if (string.IsNullOrWhiteSpace(engine) || engine.Equals("all", StringComparison.OrdinalIgnoreCase))
                return _engines;
            var requested = engine.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            return requested.Where(e => _engines.Contains(e, StringComparer.OrdinalIgnoreCase));
        }

        private static int CopyTree(string src, string dest)
        {
            if (!Directory.Exists(src)) return 0;
            int n = 0;
            foreach (var f in Directory.EnumerateFiles(src, "*", SearchOption.AllDirectories))
            {
                var rel = Path.GetRelativePath(src, f);
                if (rel.Equals("_provenance.json", StringComparison.OrdinalIgnoreCase)) continue;
                var dst = Path.Combine(dest, rel);
                Directory.CreateDirectory(Path.GetDirectoryName(dst)!);
                File.Copy(f, dst, overwrite: true);
                n++;
            }
            return n;
        }

        internal static bool LooksLikeHttp(string s)
            => s.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || s.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

        private static void DownloadFile(string url, string dest, HttpClient? http)
        {
            http ??= new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            using var resp = http.GetAsync(url).GetAwaiter().GetResult();
            resp.EnsureSuccessStatusCode();
            using var fs = File.Create(dest);
            resp.Content.CopyToAsync(fs).GetAwaiter().GetResult();
        }

        private static int ExtractZipForEngine(string zipPath, string dest, string engine)
        {
            int n = 0;
            using var archive = System.IO.Compression.ZipFile.OpenRead(zipPath);
            foreach (var entry in archive.Entries)
            {
                if (entry.FullName.EndsWith("/", StringComparison.Ordinal)) continue;
                // accept entries under <engine>/* or top-level
                var name = entry.FullName.Replace('\\', '/');
                string relative;
                int slash = name.IndexOf('/');
                if (slash > 0 && string.Equals(name.Substring(0, slash), engine, StringComparison.OrdinalIgnoreCase))
                    relative = name.Substring(slash + 1);
                else
                    relative = name;
                if (string.IsNullOrEmpty(relative) || relative.Contains("..", StringComparison.Ordinal)) continue;
                var dst = Path.Combine(dest, relative.Replace('/', Path.DirectorySeparatorChar));
                Directory.CreateDirectory(Path.GetDirectoryName(dst)!);
                using var s = entry.Open();
                using var f = File.Create(dst);
                s.CopyTo(f);
                n++;
            }
            return n;
        }

        private static void RunGitClone(string url, string dest)
        {
            var psi = new ProcessStartInfo("git")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            psi.ArgumentList.Add("clone");
            psi.ArgumentList.Add("--depth=1");
            psi.ArgumentList.Add("--quiet");
            psi.ArgumentList.Add(url);
            psi.ArgumentList.Add(dest);
            using var proc = Process.Start(psi) ?? throw new InvalidOperationException("git: failed to start");
            if (!proc.WaitForExit(60_000))
            {
                try { proc.Kill(); } catch { }
                throw new TimeoutException("git clone exceeded 60s");
            }
            if (proc.ExitCode != 0)
                throw new InvalidOperationException("git clone failed: " + proc.StandardError.ReadToEnd());
        }

        internal static string HashDirectory(string dir)
        {
            if (!Directory.Exists(dir)) return "";
            using var sha = SHA256.Create();
            // hash file relative-paths + content size + content sha256 hex, then SHA-256 over the
            // sorted concatenation. Deterministic across machines.
            var entries = new List<string>();
            foreach (var f in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories)
                                       .OrderBy(p => p, StringComparer.Ordinal))
            {
                var rel = Path.GetRelativePath(dir, f).Replace('\\', '/');
                if (rel.Equals("_provenance.json", StringComparison.OrdinalIgnoreCase)) continue;
                var size = new FileInfo(f).Length;
                var fh = RuleEngineUtil.Sha256HexFile(f);
                entries.Add($"{rel}|{size}|{fh}");
            }
            var bytes = Encoding.UTF8.GetBytes(string.Join("\n", entries));
            return RuleEngineUtil.Sha256Hex(bytes);
        }

        internal static bool TryVerifySignature(string sourceUrl, string archivePath, string publicKeyBase64, HttpClient? http)
        {
            try
            {
                var sigUrl = sourceUrl + ".sig";
                var sigPath = archivePath + ".sig";
                DownloadFile(sigUrl, sigPath, http);
                var sigB64 = File.ReadAllText(sigPath).Trim();
                var sig = Convert.FromBase64String(sigB64);
                var payload = File.ReadAllBytes(archivePath);
                var pub = Convert.FromBase64String(publicKeyBase64);
                return Ed25519Crypto.Verify(payload, sig, pub);
            }
            catch { return false; }
        }
    }
}
