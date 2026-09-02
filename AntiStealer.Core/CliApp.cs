// PR 6 — Section 7 (CLI):
//   7.1  Modern CLI framework — Spectre.Console.Cli (replaces the hand-rolled
//        switch-based parser in `Cli.Run`).
//   7.2  Sub-commands: scan / diff / watch / version / rules update /
//        cache clear / license verify / update check / ci-scan.
//   7.3  Interactive TUI mode (Spectre live + tables).
//   7.4  Progress bar + ETA + MB/s throughput.
//   7.5  NDJSON output (`--ndjson`) for SIEM pipelines.
//   7.6  Exit codes by policy (0 clean / 1 suspicious / 2 error / 3 license
//        missing). See `CliExitCodes`.
//   7.7  Watch mode — `FileSystemWatcher` with debounce.
//   7.8  CI-friendly mode — `ci-scan --threshold high --fail-on high`.
//
// All of the heavy lifting (target enumeration, parallel analyze, format
// dispatch) is factored into the `ScanRunner` helper so unit tests can
// drive the same pipeline without going through `CommandApp.Run(string[])`.

using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Compression;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Spectre.Console;
using Spectre.Console.Cli;

namespace AntiStealerOneExe
{
    // ---------- Exit-code policy (section 7.6) -----------------------------

    /// <summary>
    /// Stable, documented exit codes for any CLI consumer (CI pipelines,
    /// shell wrappers, schedulers). Treat these as the contract.
    /// </summary>
    public static class CliExitCodes
    {
        /// <summary>No file matched the configured fail-threshold.</summary>
        public const int Clean            = 0;
        /// <summary>At least one file met-or-exceeded the fail-threshold.</summary>
        public const int Suspicious       = 1;
        /// <summary>Unexpected runtime error (bad args, IO failure, …).</summary>
        public const int Error            = 2;
        /// <summary>A command required a license seat the caller does not hold.</summary>
        public const int LicenseMissing   = 3;
    }

    /// <summary>
    /// Risk threshold bands used by --threshold / --fail-on flags.
    /// Maps cleanly to <see cref="RiskLevel"/> but tolerates extra spellings
    /// (`error` is treated as `high` because errored files are typically
    /// failures-of-analysis we want to surface in CI).
    /// </summary>
    public enum RiskBand { Low, Medium, High }

    public static class RiskBandExtensions
    {
        public static bool TryParse(string? s, out RiskBand band)
        {
            band = RiskBand.High;
            if (string.IsNullOrWhiteSpace(s)) return false;
            switch (s.Trim().ToLowerInvariant())
            {
                case "low": case "l": case "0":         band = RiskBand.Low;    return true;
                case "med": case "medium": case "m": case "1":
                                                         band = RiskBand.Medium; return true;
                case "high": case "h": case "error":
                case "err": case "2": case "3":          band = RiskBand.High;   return true;
                default:                                 return false;
            }
        }

        /// <summary>
        /// True when the result is at-or-above the configured band. ERROR file-type
        /// is folded into High so CI fails noisily on broken files.
        /// </summary>
        public static bool MeetsOrExceeds(AnalysisResult r, RiskBand min)
        {
            // AnalysisResult.RiskLevel is a string ("HIGH"/"MEDIUM"/"LOW") derived from
            // RiskScore by the analyzer. ERROR is signalled via FileType="ERROR".
            if (string.Equals(r.FileType, "ERROR", StringComparison.OrdinalIgnoreCase))
                return min <= RiskBand.High;
            var tag = r.RiskLevel ?? "LOW";
            if (tag.Equals("HIGH",   StringComparison.OrdinalIgnoreCase)) return min <= RiskBand.High;
            if (tag.Equals("MEDIUM", StringComparison.OrdinalIgnoreCase)) return min <= RiskBand.Medium;
            return min <= RiskBand.Low;
        }
    }

    // ---------- ScanRunner (factored core, testable in isolation) -----------

    public sealed class ScanProgressTick
    {
        public int Done { get; init; }
        public int Total { get; init; }
        public long BytesDone { get; init; }
        public long BytesTotal { get; init; }
        public string Path { get; init; } = "";
        public TimeSpan Elapsed { get; init; }
        public double FilesPerSec => Elapsed.TotalSeconds > 0 ? Done / Elapsed.TotalSeconds : 0;
        public double MbPerSec    => Elapsed.TotalSeconds > 0 ? BytesDone / 1048576.0 / Elapsed.TotalSeconds : 0;
        public TimeSpan EtaApprox
        {
            get
            {
                if (Done <= 0 || Total <= 0) return TimeSpan.Zero;
                var perFile = Elapsed.TotalSeconds / Done;
                return TimeSpan.FromSeconds(Math.Max(0, perFile * (Total - Done)));
            }
        }
    }

    public sealed class ScanOptions
    {
        public string Target { get; init; } = "";
        public bool Recursive { get; init; }
        public bool HideLow { get; init; }
        public int MaxParallel { get; init; }
        public Action<ScanProgressTick>? OnProgress { get; init; }
        public CancellationToken Cancellation { get; init; }
    }

    public sealed class ScanOutcome
    {
        public IReadOnlyList<AnalysisResult> Results { get; init; } = Array.Empty<AnalysisResult>();
        public int FilesEnumerated { get; init; }
        public TimeSpan Duration { get; init; }
        public long BytesScanned { get; init; }
    }

    /// <summary>
    /// Core scan loop — testable without Spectre/CommandApp. Mirrors the
    /// behaviour of the legacy <see cref="Cli"/> implementation but exposes a
    /// progress callback (section 7.4) and accepts a cancellation token.
    /// </summary>
    public static class ScanRunner
    {
        private static readonly HashSet<string> AllowedExts = new(StringComparer.OrdinalIgnoreCase)
        {
            ".asi", ".dll", ".exe", ".sys", ".ocx", ".cpl", ".scr",
            ".msi", ".msix", ".appx", ".7z", ".rar", ".gz", ".tar",
            ".so", ".dylib",
            ".hta", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".lua",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf",
            ".zip", ".jar", ".apk",
        };

        public static List<string> ExpandTarget(string target, bool recursive)
        {
            var list = new List<string>();
            if (string.IsNullOrWhiteSpace(target)) return list;
            try
            {
                if (File.Exists(target))
                {
                    list.Add(Path.GetFullPath(target));
                }
                else if (Directory.Exists(target))
                {
                    var opt = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
                    foreach (var f in Directory.EnumerateFiles(target, "*", opt))
                    {
                        var ext = Path.GetExtension(f);
                        if (AllowedExts.Contains(ext)) list.Add(Path.GetFullPath(f));
                    }
                }
            }
            catch
            {
                // Surfaced upstream; the runner caller decides whether to log/fail.
            }
            return list;
        }

        public static ScanOutcome Run(ScanOptions options, AnalyzerUiSettings? settings = null)
        {
            settings ??= AnalyzerUiSettings.Load();
            Analyzer.EnableServerClassification = settings.EnableServerClassifier;
            Analyzer.EnableExternalRules        = settings.EnableExternalRules;
            Analyzer.MaxReadPrefixBytes         = settings.MaxReadPrefixMb * 1024 * 1024;
            Analyzer.MaxAsciiStrings            = settings.MaxAsciiStrings;
            Analyzer.MaxUnicodeStrings          = settings.MaxUnicodeStrings;
            Analyzer.MaxExtractedUrls           = settings.MaxUrls;

            var files = ExpandTarget(options.Target, options.Recursive);
            long bytesTotal = 0;
            foreach (var f in files) { try { bytesTotal += new FileInfo(f).Length; } catch { } }

            int dop = options.MaxParallel > 0
                ? options.MaxParallel
                : Math.Max(1, settings.MaxParallelism > 0 ? settings.MaxParallelism : Environment.ProcessorCount);

            var results   = new ConcurrentBag<AnalysisResult>();
            int done      = 0;
            long bytesDone = 0;
            var sw        = Stopwatch.StartNew();

            try
            {
                Parallel.ForEach(
                    files,
                    new ParallelOptions
                    {
                        MaxDegreeOfParallelism = dop,
                        CancellationToken      = options.Cancellation,
                    },
                    path =>
                    {
                        AnalysisResult r;
                        try { r = Analyzer.Analyze(path, path); }
                        catch (Exception ex) { r = AnalysisResult.Error(path, ex.Message); }

                        try { Analyzer.EnrichWithCloudAsync(r, settings, options.Cancellation).GetAwaiter().GetResult(); }
                        catch { }
                        try { r.RiskScore = Analyzer.ScorePublic(r); r.FinalizeFlags(); }
                        catch { }

                        long sz = 0; try { sz = new FileInfo(path).Length; } catch { }
                        Interlocked.Add(ref bytesDone, sz);
                        int d = Interlocked.Increment(ref done);

                        if (!(options.HideLow && r.RiskScore < 40)) results.Add(r);

                        var tick = new ScanProgressTick
                        {
                            Done       = d,
                            Total      = files.Count,
                            BytesDone  = Interlocked.Read(ref bytesDone),
                            BytesTotal = bytesTotal,
                            Path       = path,
                            Elapsed    = sw.Elapsed,
                        };
                        try { options.OnProgress?.Invoke(tick); } catch { }
                    });
            }
            catch (OperationCanceledException) { /* honour the token */ }

            sw.Stop();
            return new ScanOutcome
            {
                Results          = results.OrderByDescending(r => r.RiskScore).ToList(),
                FilesEnumerated  = files.Count,
                Duration         = sw.Elapsed,
                BytesScanned     = Interlocked.Read(ref bytesDone),
            };
        }
    }

    // ---------- Output (formats + ndjson, section 7.5) ---------------------

    /// <summary>
    /// Encapsulates the format dispatch matrix so the scan / ci-scan / watch
    /// commands all serialise results identically. Returns one of the
    /// <see cref="CliExitCodes"/> values.
    /// </summary>
    public static class ScanOutputWriter
    {
        public static int Write(
            IReadOnlyList<AnalysisResult> results,
            string format,
            string? outPath,
            string? batchDir,
            bool ndjson,
            TextWriter stdout,
            TextWriter stderr)
        {
            try
            {
                if (ndjson)
                {
                    var sb = new StringBuilder();
                    foreach (var r in results) sb.AppendLine(JsonSerializer.Serialize(r, JsonOptionsRegistry.CamelCase));
                    var text = sb.ToString();
                    if (string.IsNullOrEmpty(outPath)) stdout.Write(text);
                    else File.WriteAllText(outPath, text, new UTF8Encoding(false));
                    return CliExitCodes.Clean;
                }

                switch ((format ?? "json").ToLowerInvariant())
                {
                    case "json":
                    {
                        var text = ReportWriter.ToJson(results);
                        if (string.IsNullOrEmpty(outPath)) stdout.WriteLine(text);
                        else File.WriteAllText(outPath, text, Encoding.UTF8);
                        break;
                    }
                    case "html":
                    {
                        var text = ReportWriter.ToHtml(results);
                        if (string.IsNullOrEmpty(outPath)) stdout.WriteLine(text);
                        else File.WriteAllText(outPath, text, Encoding.UTF8);
                        break;
                    }
                    case "pdf":
                    {
                        if (string.IsNullOrEmpty(outPath)) { stderr.WriteLine("--pdf requires --out <file>."); return CliExitCodes.Error; }
                        File.WriteAllBytes(outPath, ReportWriter.ToPdfBytes(results));
                        break;
                    }
                    case "stix":
                    {
                        var text = ReportWriter.ToStix(results);
                        if (string.IsNullOrEmpty(outPath)) stdout.WriteLine(text);
                        else File.WriteAllText(outPath, text, Encoding.UTF8);
                        break;
                    }
                    case "sarif":
                    {
                        var text = ReportWriter.ToSarif(results);
                        if (string.IsNullOrEmpty(outPath)) stdout.WriteLine(text);
                        else File.WriteAllText(outPath, text, Encoding.UTF8);
                        break;
                    }
                    case "csv":
                    {
                        var text = ReportWriter.ToCsv(results);
                        if (string.IsNullOrEmpty(outPath)) stdout.WriteLine(text);
                        else File.WriteAllText(outPath, text, Encoding.UTF8);
                        break;
                    }
                    case "batch-html":
                    {
                        if (string.IsNullOrEmpty(batchDir)) { stderr.WriteLine("--batch-html requires --batch-out <dir>."); return CliExitCodes.Error; }
                        ReportWriter.WriteBatchHtml(results, batchDir);
                        break;
                    }
                    // ──────────────────────────────────────────────────────
                    // Section 11.5 — XLSX (binary, requires --out).
                    // ──────────────────────────────────────────────────────
                    case "xlsx":
                    {
                        if (string.IsNullOrEmpty(outPath)) { stderr.WriteLine("--format xlsx requires --out <file>."); return CliExitCodes.Error; }
                        File.WriteAllBytes(outPath, ReportsV2.ToXlsx(results));
                        break;
                    }
                    // ──────────────────────────────────────────────────────
                    // Section 11.6 — Elastic Common Schema NDJSON.
                    // ──────────────────────────────────────────────────────
                    case "ecs":
                    case "ecs-ndjson":
                    {
                        var text = ReportsV2.ToEcsNdjson(results);
                        if (string.IsNullOrEmpty(outPath)) stdout.Write(text);
                        else File.WriteAllText(outPath, text, new UTF8Encoding(false));
                        break;
                    }
                    // ──────────────────────────────────────────────────────
                    // Section 11.7 — Splunk HEC envelope.
                    // ──────────────────────────────────────────────────────
                    case "splunk":
                    case "splunk-hec":
                    {
                        var text = ReportsV2.ToSplunkHec(results);
                        if (string.IsNullOrEmpty(outPath)) stdout.Write(text);
                        else File.WriteAllText(outPath, text, new UTF8Encoding(false));
                        break;
                    }
                    // ──────────────────────────────────────────────────────
                    // Section 11.8 — chat-webhook payloads (auto-detect or
                    // explicit per-platform).
                    // ──────────────────────────────────────────────────────
                    case "slack":
                    {
                        var text = ReportsV2.ToWebhookPayload(results, ReportsV2.WebhookKind.Slack);
                        if (string.IsNullOrEmpty(outPath)) stdout.WriteLine(text);
                        else File.WriteAllText(outPath, text, Encoding.UTF8);
                        break;
                    }
                    case "teams":
                    {
                        var text = ReportsV2.ToWebhookPayload(results, ReportsV2.WebhookKind.Teams);
                        if (string.IsNullOrEmpty(outPath)) stdout.WriteLine(text);
                        else File.WriteAllText(outPath, text, Encoding.UTF8);
                        break;
                    }
                    case "discord":
                    {
                        var text = ReportsV2.ToWebhookPayload(results, ReportsV2.WebhookKind.Discord);
                        if (string.IsNullOrEmpty(outPath)) stdout.WriteLine(text);
                        else File.WriteAllText(outPath, text, Encoding.UTF8);
                        break;
                    }
                    // ──────────────────────────────────────────────────────
                    // Section 11.9 — Jira REST v3 issue payloads (NDJSON,
                    // one body per HIGH-or-MEDIUM result, ready for `curl
                    // -X POST` against /rest/api/3/issue).
                    // ──────────────────────────────────────────────────────
                    case "jira":
                    {
                        var sb = new StringBuilder();
                        var hi = results.Where(r => r.RiskScore >= 40).ToArray();
                        foreach (var r in hi)
                            sb.AppendLine(ReportsV2.ToJiraIssuePayload(r, projectKey: "SEC"));
                        var text = sb.ToString();
                        if (string.IsNullOrEmpty(outPath)) stdout.Write(text);
                        else File.WriteAllText(outPath, text, new UTF8Encoding(false));
                        break;
                    }
                    // ──────────────────────────────────────────────────────
                    // Section 11.10 — Suricata IDS rules.
                    // ──────────────────────────────────────────────────────
                    case "suricata":
                    case "rules":
                    {
                        var text = ReportsV2.ToSuricataRules(results);
                        if (string.IsNullOrEmpty(outPath)) stdout.Write(text);
                        else File.WriteAllText(outPath, text, new UTF8Encoding(false));
                        break;
                    }
                    default:
                        stderr.WriteLine("Unknown --format: " + format);
                        return CliExitCodes.Error;
                }
                return CliExitCodes.Clean;
            }
            catch (Exception ex)
            {
                stderr.WriteLine("Output error: " + ex.Message);
                return CliExitCodes.Error;
            }
        }
    }

    // ---------- Diff helper (section 7.2: `antistealer diff`) --------------

    public sealed class ScanDiffEntry
    {
        public string Sha256 { get; init; } = "";
        public string FilePath { get; init; } = "";
        public int OldScore { get; init; }
        public int NewScore { get; init; }
        public string Change { get; init; } = ""; // "added" | "removed" | "score-changed"
    }

    public static class ScanDiff
    {
        public static List<ScanDiffEntry> Compute(IReadOnlyList<AnalysisResult> oldR, IReadOnlyList<AnalysisResult> newR)
        {
            string KeyOf(AnalysisResult r) => string.IsNullOrEmpty(r.Sha256) ? r.FilePath : r.Sha256;
            var oldMap = oldR.GroupBy(KeyOf).ToDictionary(g => g.Key, g => g.First());
            var newMap = newR.GroupBy(KeyOf).ToDictionary(g => g.Key, g => g.First());
            var diffs = new List<ScanDiffEntry>();
            foreach (var kv in newMap)
            {
                if (!oldMap.TryGetValue(kv.Key, out var prev))
                {
                    diffs.Add(new ScanDiffEntry { Sha256 = kv.Value.Sha256 ?? "", FilePath = kv.Value.FilePath ?? "",
                        OldScore = 0, NewScore = kv.Value.RiskScore, Change = "added" });
                }
                else if (prev.RiskScore != kv.Value.RiskScore)
                {
                    diffs.Add(new ScanDiffEntry { Sha256 = kv.Value.Sha256 ?? "", FilePath = kv.Value.FilePath ?? "",
                        OldScore = prev.RiskScore, NewScore = kv.Value.RiskScore, Change = "score-changed" });
                }
            }
            foreach (var kv in oldMap)
                if (!newMap.ContainsKey(kv.Key))
                    diffs.Add(new ScanDiffEntry { Sha256 = kv.Value.Sha256 ?? "", FilePath = kv.Value.FilePath ?? "",
                        OldScore = kv.Value.RiskScore, NewScore = 0, Change = "removed" });
            return diffs;
        }

        public static List<AnalysisResult> LoadJson(string path)
        {
            var raw = File.ReadAllText(path);
            using var doc = JsonDocument.Parse(raw);
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
                return JsonSerializer.Deserialize<List<AnalysisResult>>(raw, JsonOptionsRegistry.Indented) ?? new List<AnalysisResult>();
            // Some report formats wrap the array under "results"; tolerate that.
            if (doc.RootElement.TryGetProperty("results", out var arr) && arr.ValueKind == JsonValueKind.Array)
                return JsonSerializer.Deserialize<List<AnalysisResult>>(arr.GetRawText(), JsonOptionsRegistry.Indented)
                       ?? new List<AnalysisResult>();
            throw new InvalidDataException("Unrecognised JSON shape; expected `[…]` or `{ \"results\": [...] }`.");
        }
    }

    // ---------- Spectre.Console.Cli: settings ------------------------------

    public class ScanSettings : CommandSettings
    {
        [Description("Path to a file or directory.")]
        [CommandArgument(0, "<PATH>")]
        public string Path { get; set; } = "";

        [Description("Descend into subdirectories.")]
        [CommandOption("-r|--recursive")]
        public bool Recursive { get; set; }

        [Description("Drop results with RiskScore < 40.")]
        [CommandOption("--hide-low")]
        public bool HideLow { get; set; }

        [Description("Override worker count (default: CPU count).")]
        [CommandOption("-j|--max-parallel <N>")]
        public int MaxParallel { get; set; }

        [Description("Output format: json|html|pdf|stix|sarif|csv|batch-html|xlsx|ecs|splunk-hec|suricata|slack|teams|discord|jira.")]
        [CommandOption("--format <FMT>")]
        public string? Format { get; set; }

        [Description("Emit NDJSON (one result per line) — for SIEM ingestion.")]
        [CommandOption("--ndjson")]
        public bool Ndjson { get; set; }

        // Section 11.8 — chat-webhook push. Auto-detects Slack / Teams /
        // Discord by URL host. Posts top-5 highest-risk results.
        [Description("Push top-5 results to a Slack / Teams / Discord webhook URL.")]
        [CommandOption("--webhook <URL>")]
        public string? WebhookUrl { get; set; }

        // Section 11.7 — Splunk HEC push.
        [Description("Push ECS-formatted events to Splunk HTTP Event Collector.")]
        [CommandOption("--splunk-hec <URL>")]
        public string? SplunkHecUrl { get; set; }

        [Description("Splunk HEC token (or set $SPLUNK_HEC_TOKEN).")]
        [CommandOption("--splunk-hec-token <TOKEN>")]
        public string? SplunkHecToken { get; set; }

        // Section 11.9 — Jira push.
        [Description("Jira Cloud base URL (e.g. https://example.atlassian.net) for HIGH-result tickets.")]
        [CommandOption("--jira-url <URL>")]
        public string? JiraUrl { get; set; }

        [Description("Jira Cloud email (or $JIRA_EMAIL).")]
        [CommandOption("--jira-email <EMAIL>")]
        public string? JiraEmail { get; set; }

        [Description("Jira Cloud API token (or $JIRA_TOKEN).")]
        [CommandOption("--jira-token <TOKEN>")]
        public string? JiraToken { get; set; }

        [Description("Jira project key (e.g. SEC).")]
        [CommandOption("--jira-project <KEY>")]
        public string? JiraProject { get; set; }

        [Description("Write to <FILE> instead of stdout.")]
        [CommandOption("-o|--out <FILE>")]
        public string? OutPath { get; set; }

        [Description("Output directory for --format batch-html.")]
        [CommandOption("--batch-out <DIR>")]
        public string? BatchOut { get; set; }

        [Description("Disable Spectre live progress / colors (default: auto).")]
        [CommandOption("--no-progress")]
        public bool NoProgress { get; set; }

        [Description("Force-enable Spectre live progress / colors even when stdout is redirected.")]
        [CommandOption("--progress")]
        public bool ForceProgress { get; set; }

        [Description("Format-aliases. Equivalent to --format <name>.")]
        [CommandOption("--json")]
        public bool Json { get; set; }
        [CommandOption("--html")]    public bool Html { get; set; }
        [CommandOption("--pdf")]     public bool Pdf  { get; set; }
        [CommandOption("--stix")]    public bool Stix { get; set; }
        [CommandOption("--sarif")]   public bool Sarif { get; set; }
        [CommandOption("--csv")]     public bool Csv  { get; set; }
        [CommandOption("--batch-html")] public bool BatchHtml { get; set; }

        // Section 9 (PR 9) — intel orchestrator flags.
        [Description("Local TI feed (one indicator per line, '#' comments).")]
        [CommandOption("--local-ti <FILE>")]
        public string? LocalTiFile { get; set; }

        [Description("Persist intel-orchestrator cache to this JSON file.")]
        [CommandOption("--intel-cache <FILE>")]
        public string? IntelCachePath { get; set; }

        [Description("Read a libpcap capture and enrich URL/IP/domain IOCs from it.")]
        [CommandOption("--pcap <FILE>")]
        public string? PcapFile { get; set; }

        [Description("Enable ThreatFox (abuse.ch) provider for URL/IP/SHA256 lookups.")]
        [CommandOption("--threatfox")]
        public bool EnableThreatFox { get; set; }

        [Description("Enable OTX (AlienVault) provider (requires API key).")]
        [CommandOption("--otx-key <KEY>")]
        public string? OtxApiKey { get; set; }

        public string ResolveFormat()
        {
            if (!string.IsNullOrEmpty(Format)) return Format.ToLowerInvariant();
            if (Html)      return "html";
            if (Pdf)       return "pdf";
            if (Stix)      return "stix";
            if (Sarif)     return "sarif";
            if (Csv)       return "csv";
            if (BatchHtml) return "batch-html";
            return "json";
        }
    }

    public sealed class CiScanSettings : ScanSettings
    {
        [Description("Minimum risk band to include in output: low|medium|high.")]
        [CommandOption("--threshold <BAND>")]
        public string Threshold { get; set; } = "low";

        [Description("Fail (exit 1) if any result is at-or-above this band: low|medium|high.")]
        [CommandOption("--fail-on <BAND>")]
        public string FailOn { get; set; } = "high";
    }

    public sealed class WatchSettings : ScanSettings
    {
        [Description("Quiet window in ms after the last change before scanning a file (default 750).")]
        [CommandOption("--debounce-ms <N>")]
        public int DebounceMs { get; set; } = 750;

        [Description("Stop after the first scan completes (useful for tests).")]
        [CommandOption("--once")]
        public bool Once { get; set; }
    }

    public sealed class DiffSettings : CommandSettings
    {
        [Description("Path to the old JSON scan report.")]
        [CommandArgument(0, "<OLD_REPORT>")]
        public string OldPath { get; set; } = "";

        [Description("Path to the new JSON scan report.")]
        [CommandArgument(1, "<NEW_REPORT>")]
        public string NewPath { get; set; } = "";

        [Description("Output format: json|ndjson|table|markdown|html (default: table).")]
        [CommandOption("--format <FMT>")]
        public string Format { get; set; } = "table";

        [Description("Write to <FILE> instead of stdout.")]
        [CommandOption("-o|--out <FILE>")]
        public string? OutPath { get; set; }
    }

    public sealed class VersionSettings : CommandSettings
    {
        [Description("Emit machine-readable JSON instead of human text.")]
        [CommandOption("--json")]
        public bool Json { get; set; }
    }

    public sealed class LicenseVerifySettings : CommandSettings
    {
        [Description("Path to the license JSON.")]
        [CommandArgument(0, "<LICENSE_FILE>")]
        public string Path { get; set; } = "";

        [Description("Override HMAC key (otherwise resolved from env / embedded).")]
        [CommandOption("--hmac-key <KEY>")]
        public string? HmacKey { get; set; }

        [Description("Override base64-encoded Ed25519 public key.")]
        [CommandOption("--ed25519-pubkey <B64>")]
        public string? Ed25519PublicKey { get; set; }
    }

    public sealed class UpdateCheckSettings : CommandSettings
    {
        [Description("Release manifest URL.")]
        [CommandArgument(0, "<MANIFEST_URL>")]
        public string ManifestUrl { get; set; } = "";

        [Description("Override HMAC key.")]
        [CommandOption("--hmac-key <KEY>")]
        public string? HmacKey { get; set; }

        [Description("Override base64-encoded Ed25519 public key.")]
        [CommandOption("--ed25519-pubkey <B64>")]
        public string? Ed25519PublicKey { get; set; }
    }

    public sealed class RulesUpdateSettings : CommandSettings
    {
        [Description("Source URL, directory, or git+https://... for rule packs.")]
        [CommandOption("--source <URL_OR_DIR>")]
        public string? Source { get; set; }

        [Description("Where to write the rules (default: %APPDATA%/AntiStealer/rules).")]
        [CommandOption("--dest <DIR>")]
        public string? Dest { get; set; }

        [Description("Which engine pack to refresh: sigma | capa | yara | all (default).")]
        [CommandOption("--engine <ENGINE>")]
        public string Engine { get; set; } = "all";

        [Description("Base64-encoded Ed25519 public key used to verify the .sig sidecar.")]
        [CommandOption("--public-key <B64>")]
        public string? PublicKey { get; set; }

        [Description("Stamp this version string into _provenance.json.")]
        [CommandOption("--version <VER>")]
        public string? Version { get; set; }

        [Description("Skip signature verification (NOT recommended).")]
        [CommandOption("--insecure")]
        public bool Insecure { get; set; }
    }

    public sealed class CacheClearSettings : CommandSettings
    {
        [Description("Cache directory (default: %APPDATA%/AntiStealer/cache).")]
        [CommandOption("--dir <DIR>")]
        public string? Dir { get; set; }
    }

    public sealed class CompletionSettings : CommandSettings
    {
        [Description("Shell: bash | zsh | powershell.")]
        [CommandArgument(0, "<SHELL>")]
        public string Shell { get; set; } = "bash";
    }

    // ---------- Spectre.Console.Cli: commands ------------------------------

    public sealed class ScanCommand : Command<ScanSettings>
    {
        public override int Execute(CommandContext ctx, ScanSettings s)
            => CliApp.RunScan(s, fallbackFailBand: null);
    }

    public sealed class CiScanCommand : Command<CiScanSettings>
    {
        public override int Execute(CommandContext ctx, CiScanSettings s)
        {
            if (!RiskBandExtensions.TryParse(s.FailOn, out var failBand))
            {
                AnsiConsole.MarkupLineInterpolated($"[red]ci-scan: invalid --fail-on `{s.FailOn}`[/]");
                return CliExitCodes.Error;
            }
            return CliApp.RunScan(s, fallbackFailBand: failBand);
        }
    }

    public sealed class DiffCommand : Command<DiffSettings>
    {
        public override int Execute(CommandContext ctx, DiffSettings s)
        {
            try
            {
                var oldR = ScanDiff.LoadJson(s.OldPath);
                var newR = ScanDiff.LoadJson(s.NewPath);
                var diffs = ScanDiff.Compute(oldR, newR);

                switch (s.Format.ToLowerInvariant())
                {
                    case "json":
                    {
                        var text = JsonSerializer.Serialize(diffs, JsonOptionsRegistry.Indented);
                        if (string.IsNullOrEmpty(s.OutPath)) Console.Out.WriteLine(text);
                        else File.WriteAllText(s.OutPath, text, Encoding.UTF8);
                        break;
                    }
                    case "ndjson":
                    {
                        var sb = new StringBuilder();
                        foreach (var d in diffs) sb.AppendLine(JsonSerializer.Serialize(d, JsonOptionsRegistry.CamelCase));
                        if (string.IsNullOrEmpty(s.OutPath)) Console.Out.Write(sb.ToString());
                        else File.WriteAllText(s.OutPath, sb.ToString(), new UTF8Encoding(false));
                        break;
                    }
                    // Section 11.11 — diff report renderers backed by
                    // ReportWritersExtended.DiffJsonReports.
                    case "html":
                    case "markdown":
                    case "md":
                    {
                        // Re-parse the input as raw JSON so we can pass it to
                        // the DiffJsonReports helper (which works on
                        // free-form JSON, not the typed ScanDiffEntry list).
                        var summary = ReportWritersExtended.DiffJsonReports(
                            File.ReadAllText(s.OldPath),
                            File.ReadAllText(s.NewPath));
                        var text = s.Format.ToLowerInvariant() == "html"
                            ? ReportsV2.DiffToHtml(summary)
                            : ReportWritersExtended.DiffToMarkdown(summary);
                        if (string.IsNullOrEmpty(s.OutPath)) Console.Out.WriteLine(text);
                        else File.WriteAllText(s.OutPath, text, Encoding.UTF8);
                        break;
                    }
                    default:
                    {
                        var table = new Table().AddColumns("change", "score(old → new)", "sha256", "path");
                        foreach (var d in diffs)
                        {
                            var color = d.Change switch
                            {
                                "added"         => "red",
                                "removed"       => "green",
                                "score-changed" => d.NewScore > d.OldScore ? "yellow" : "blue",
                                _               => "default",
                            };
                            table.AddRow(
                                $"[{color}]{Markup.Escape(d.Change)}[/]",
                                Markup.Escape($"{d.OldScore,3} → {d.NewScore,3}"),
                                Markup.Escape(d.Sha256.Length >= 12 ? d.Sha256[..12] : d.Sha256),
                                Markup.Escape(d.FilePath));
                        }
                        AnsiConsole.Write(table);
                        AnsiConsole.WriteLine($"{diffs.Count} change(s).");
                        break;
                    }
                }
                return CliExitCodes.Clean;
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLineInterpolated($"[red]diff: {ex.Message}[/]");
                return CliExitCodes.Error;
            }
        }
    }

    public sealed class WatchCommand : Command<WatchSettings>
    {
        public override int Execute(CommandContext ctx, WatchSettings s)
        {
            if (string.IsNullOrWhiteSpace(s.Path) || !Directory.Exists(s.Path))
            {
                AnsiConsole.MarkupLineInterpolated($"[red]watch: directory not found: {Markup.Escape(s.Path)}[/]");
                return CliExitCodes.Error;
            }

            var debounce = TimeSpan.FromMilliseconds(Math.Max(50, s.DebounceMs));
            var pending = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
            using var watcher = new FileSystemWatcher(s.Path)
            {
                IncludeSubdirectories = s.Recursive,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
                EnableRaisingEvents = true,
            };

            void Enqueue(string p) => pending[p] = DateTime.UtcNow;
            watcher.Created += (_, e) => Enqueue(e.FullPath);
            watcher.Changed += (_, e) => Enqueue(e.FullPath);
            watcher.Renamed += (_, e) => Enqueue(e.FullPath);

            AnsiConsole.MarkupLineInterpolated(
                $"[green]watch[/] {Markup.Escape(s.Path)} (recursive={s.Recursive}, debounce={s.DebounceMs}ms). Ctrl+C to exit.");
            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

            while (!cts.IsCancellationRequested)
            {
                try { Task.Delay(debounce, cts.Token).GetAwaiter().GetResult(); }
                catch (OperationCanceledException) { break; }

                var due = pending
                    .Where(kv => DateTime.UtcNow - kv.Value >= debounce)
                    .Select(kv => kv.Key)
                    .ToList();
                if (due.Count == 0) { if (s.Once) break; continue; }

                foreach (var p in due) pending.TryRemove(p, out _);
                foreach (var p in due)
                {
                    var sub = new ScanSettings
                    {
                        Path        = p,
                        Recursive   = false,
                        HideLow     = s.HideLow,
                        MaxParallel = s.MaxParallel,
                        Format      = s.Format,
                        OutPath     = null,            // always print to stdout in watch mode
                        Ndjson      = s.Ndjson,
                        NoProgress  = true,            // keep watch-mode output non-interactive
                    };
                    try { CliApp.RunScan(sub, fallbackFailBand: null); }
                    catch (Exception ex)
                    {
                        AnsiConsole.MarkupLineInterpolated($"[red]watch: scan error for {Markup.Escape(p)}: {Markup.Escape(ex.Message)}[/]");
                    }
                }

                if (s.Once) break;
            }
            return CliExitCodes.Clean;
        }
    }

    public sealed class VersionCommand : Command<VersionSettings>
    {
        public override int Execute(CommandContext ctx, VersionSettings s)
        {
            var asm        = typeof(VersionCommand).Assembly;
            var infoVer    = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0";
            var fileVer    = asm.GetCustomAttribute<AssemblyFileVersionAttribute>()?.Version ?? "0.0.0";
            var productVer = ProductInfo.Version;
            var runtime    = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription;
            var os         = System.Runtime.InteropServices.RuntimeInformation.OSDescription;

            if (s.Json)
            {
                var obj = new
                {
                    product = "AntiStealer",
                    version = productVer,
                    informationalVersion = infoVer,
                    fileVersion = fileVer,
                    runtime,
                    os,
                };
                Console.Out.WriteLine(JsonSerializer.Serialize(obj, JsonOptionsRegistry.Indented));
                return CliExitCodes.Clean;
            }

            AnsiConsole.MarkupLineInterpolated($"[bold]AntiStealer[/] {Markup.Escape(productVer)}");
            AnsiConsole.WriteLine($"informational: {infoVer}");
            AnsiConsole.WriteLine($"file:          {fileVer}");
            AnsiConsole.WriteLine($"runtime:       {runtime}");
            AnsiConsole.WriteLine($"os:            {os}");
            return CliExitCodes.Clean;
        }
    }

    public sealed class LicenseVerifyCommand : Command<LicenseVerifySettings>
    {
        public override int Execute(CommandContext ctx, LicenseVerifySettings s)
        {
            try
            {
                if (!File.Exists(s.Path))
                {
                    AnsiConsole.MarkupLineInterpolated($"[red]license verify: file not found: {Markup.Escape(s.Path)}[/]");
                    return CliExitCodes.LicenseMissing;
                }

                var hmac = string.IsNullOrEmpty(s.HmacKey) ? LicenseVerifier.ResolveHmacKey() : s.HmacKey;
                var ed25 = string.IsNullOrEmpty(s.Ed25519PublicKey) ? LicenseVerifier.ResolveEd25519PublicKeyBase64() : s.Ed25519PublicKey;
                var lic  = LicenseVerifier.Load(s.Path, hmac, ed25, out var reason);
                if (lic == null)
                {
                    AnsiConsole.MarkupLineInterpolated($"[red]license verify: {Markup.Escape(reason ?? "invalid")}[/]");
                    return CliExitCodes.LicenseMissing;
                }
                AnsiConsole.MarkupLine("[green]license verify: ok[/]");
                AnsiConsole.WriteLine($"  customer: {lic.Customer}");
                AnsiConsole.WriteLine($"  sku:      {lic.Sku}");
                AnsiConsole.WriteLine($"  expires:  {lic.Expires:u}");
                AnsiConsole.WriteLine($"  features: {string.Join(", ", lic.Features ?? new List<string>())}");
                return CliExitCodes.Clean;
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLineInterpolated($"[red]license verify: {Markup.Escape(ex.Message)}[/]");
                return CliExitCodes.Error;
            }
        }
    }

    public sealed class UpdateCheckCommand : Command<UpdateCheckSettings>
    {
        public override int Execute(CommandContext ctx, UpdateCheckSettings s)
        {
            try
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
                var hmac = string.IsNullOrEmpty(s.HmacKey) ? LicenseVerifier.ResolveHmacKey() : s.HmacKey;
                var ed25 = string.IsNullOrEmpty(s.Ed25519PublicKey) ? LicenseVerifier.ResolveEd25519PublicKeyBase64() : s.Ed25519PublicKey;
                var task = UpdateCheck.CheckAsync(s.ManifestUrl, hmac, ed25, http);
                task.GetAwaiter().GetResult();
                var manifest = task.Result;
                if (manifest == null)
                {
                    AnsiConsole.MarkupLine("[yellow]update check: manifest unreachable or invalid signature[/]");
                    return CliExitCodes.Error;
                }
                AnsiConsole.WriteLine($"latest version:   {manifest.Version}");
                AnsiConsole.WriteLine($"released:         {manifest.Released:u}");
                AnsiConsole.WriteLine($"url:              {manifest.Url}");
                AnsiConsole.WriteLine($"current version:  {ProductInfo.Version}");
                if (UpdateCheck.IsNewerThanCurrent(manifest))
                {
                    AnsiConsole.MarkupLine("[green]update available[/]");
                    return CliExitCodes.Suspicious;
                }
                AnsiConsole.MarkupLine("[green]you are on the latest release[/]");
                return CliExitCodes.Clean;
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLineInterpolated($"[red]update check: {Markup.Escape(ex.Message)}[/]");
                return CliExitCodes.Error;
            }
        }
    }

    public sealed class RulesUpdateCommand : Command<RulesUpdateSettings>
    {
        public override int Execute(CommandContext ctx, RulesUpdateSettings s)
        {
            try
            {
                var opts = new RulesUpdateOptions
                {
                    Engine = string.IsNullOrWhiteSpace(s.Engine) ? "all" : s.Engine,
                    Source = s.Source,
                    Dest = s.Dest,
                    Insecure = s.Insecure,
                    PublicKeyBase64 = s.PublicKey,
                    Version = s.Version,
                };
                var res = RulesUpdater.Update(opts);
                if (res.Errors.Count > 0)
                {
                    foreach (var e in res.Errors)
                        AnsiConsole.MarkupLineInterpolated($"[red]rules update: {Markup.Escape(e)}[/]");
                    return CliExitCodes.Error;
                }
                if (string.IsNullOrEmpty(opts.Source))
                    AnsiConsole.MarkupLineInterpolated($"[yellow]rules update: no --source given; ensured directories under {Markup.Escape(res.Dest)}[/]");
                else
                    AnsiConsole.MarkupLineInterpolated($"[green]rules update: {res.FilesCopied} file(s) for engine={Markup.Escape(opts.Engine)} → {Markup.Escape(res.Dest)} (sha256={Markup.Escape(res.Sha256.Length > 12 ? res.Sha256[..12] : res.Sha256)}…, signed={res.SignatureVerified})[/]");
                return CliExitCodes.Clean;
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLineInterpolated($"[red]rules update: {Markup.Escape(ex.Message)}[/]");
                return CliExitCodes.Error;
            }
        }
    }

    public sealed class CacheClearCommand : Command<CacheClearSettings>
    {
        public override int Execute(CommandContext ctx, CacheClearSettings s)
        {
            try
            {
                var dir = !string.IsNullOrEmpty(s.Dir) ? s.Dir
                        : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                                       "AntiStealer", "cache");
                if (!Directory.Exists(dir))
                {
                    AnsiConsole.MarkupLineInterpolated($"[green]cache clear: nothing to do (no cache at {Markup.Escape(dir)})[/]");
                    return CliExitCodes.Clean;
                }
                int n = 0;
                foreach (var f in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    try { File.Delete(f); n++; } catch { }
                }
                AnsiConsole.MarkupLineInterpolated($"[green]cache clear: removed {n} file(s) from {Markup.Escape(dir)}[/]");
                return CliExitCodes.Clean;
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLineInterpolated($"[red]cache clear: {Markup.Escape(ex.Message)}[/]");
                return CliExitCodes.Error;
            }
        }
    }

    public sealed class CompletionCommand : Command<CompletionSettings>
    {
        public override int Execute(CommandContext ctx, CompletionSettings s)
        {
            string text;
            switch (s.Shell.Trim().ToLowerInvariant())
            {
                case "bash":       text = ReportWritersExtended.ToBashCompletion();       break;
                case "zsh":        text = ReportWritersExtended.ToZshCompletion();        break;
                case "powershell":
                case "pwsh":
                case "ps":         text = ReportWritersExtended.ToPowerShellCompletion(); break;
                default:
                    AnsiConsole.MarkupLineInterpolated($"[red]completion: unsupported shell `{Markup.Escape(s.Shell)}` (use bash|zsh|powershell)[/]");
                    return CliExitCodes.Error;
            }
            Console.Out.Write(text);
            return CliExitCodes.Clean;
        }
    }

    // ---------- App glue ---------------------------------------------------

    public static class CliApp
    {
        // Section 7.4 — interpret a tick as a Spectre status string.
        public static string FormatProgress(ScanProgressTick t)
        {
            var pct = t.Total > 0 ? (int)(100.0 * t.Done / t.Total) : 0;
            return $"{t.Done}/{t.Total} ({pct,3}%)  {t.MbPerSec:0.0} MB/s  ETA {t.EtaApprox:mm\\:ss}";
        }

        public static int RunScan(ScanSettings s, RiskBand? fallbackFailBand)
        {
            try
            {
                var stdout = Console.Out;
                var stderr = Console.Error;

                bool tty            = !Console.IsOutputRedirected;
                bool showProgress   = !s.NoProgress && (s.ForceProgress || tty);
                bool isCi           = s is CiScanSettings;

                var settings = AnalyzerUiSettings.Load();
                int total    = ScanRunner.ExpandTarget(s.Path, s.Recursive).Count;
                if (total == 0)
                {
                    stderr.WriteLine("No scannable files under: " + s.Path);
                    return CliExitCodes.Error;
                }

                ScanOutcome outcome;
                if (showProgress && !isCi)
                {
                    // Section 7.3 + 7.4 — Spectre live progress with ETA + MB/s.
                    outcome = AnsiConsole.Progress()
                        .Columns(new ProgressColumn[]
                        {
                            new TaskDescriptionColumn(),
                            new ProgressBarColumn(),
                            new PercentageColumn(),
                            new RemainingTimeColumn(),
                            new SpinnerColumn(),
                        })
                        .Start(progress =>
                        {
                            var task = progress.AddTask("[green]scanning[/]", maxValue: total);
                            return ScanRunner.Run(
                                new ScanOptions
                                {
                                    Target      = s.Path,
                                    Recursive   = s.Recursive,
                                    HideLow     = s.HideLow,
                                    MaxParallel = s.MaxParallel,
                                    OnProgress  = tick =>
                                    {
                                        task.Value = tick.Done;
                                        task.Description = $"[green]scanning[/]  {tick.MbPerSec:0.0} MB/s";
                                    },
                                },
                                settings);
                        });
                }
                else
                {
                    int lastDone = 0;
                    outcome = ScanRunner.Run(
                        new ScanOptions
                        {
                            Target      = s.Path,
                            Recursive   = s.Recursive,
                            HideLow     = s.HideLow,
                            MaxParallel = s.MaxParallel,
                            OnProgress  = tick =>
                            {
                                if (s.NoProgress) return;
                                if (tick.Done - lastDone < 25 && tick.Done != tick.Total) return;
                                lastDone = tick.Done;
                                stderr.WriteLine($"  {FormatProgress(tick)}  {Path.GetFileName(tick.Path)}");
                            },
                        },
                        settings);
                }

                // Section 9 (PR 9) — intel orchestrator + PCAP enrichment.
                try { RunIntelEnrichment(s, outcome.Results, stderr); }
                catch (Exception ex) { stderr.WriteLine("intel: " + ex.Message); }

                // Threshold filtering (section 7.8: ci-scan).
                var resultsForOutput = outcome.Results;
                if (s is CiScanSettings ci &&
                    RiskBandExtensions.TryParse(ci.Threshold, out var thresh))
                {
                    resultsForOutput = outcome.Results
                        .Where(r => RiskBandExtensions.MeetsOrExceeds(r, thresh))
                        .ToList();
                }

                var fmt = s.ResolveFormat();
                int rc  = ScanOutputWriter.Write(
                    resultsForOutput, fmt, s.OutPath, s.BatchOut, s.Ndjson,
                    stdout, stderr);
                stderr.WriteLine($"done: {resultsForOutput.Count} files in {outcome.Duration.TotalSeconds:0.0}s "
                                + $"({outcome.BytesScanned / 1048576.0:0.0} MB)");
                if (rc != CliExitCodes.Clean) return rc;

                // Section 11.7 / 11.8 / 11.9 — optional sinks.
                // Best-effort: report status on stderr but never fail the
                // scan because of a downstream HTTP error.
                try { PushIntegrations(s, resultsForOutput, stderr); }
                catch (Exception ex) { stderr.WriteLine("push: " + ex.Message); }

                if (fallbackFailBand.HasValue)
                {
                    bool any = resultsForOutput.Any(r => RiskBandExtensions.MeetsOrExceeds(r, fallbackFailBand.Value));
                    return any ? CliExitCodes.Suspicious : CliExitCodes.Clean;
                }
                return CliExitCodes.Clean;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("scan: " + ex.Message);
                return CliExitCodes.Error;
            }
        }

        // Section 11.7 / 11.8 / 11.9 — push results to optional sinks after
        // the local report is written. Best-effort, synchronous; errors are
        // logged but do not change the scan's exit code.
        // Section 9 (PR 9) — orchestrator entry point. Builds an
        // IntelOrchestrator from --local-ti / --otx-key / --threatfox and
        // optionally feeds it indicators extracted from --pcap, then enriches
        // every result's per-IOC dictionary. All failures are best-effort.
        internal static void RunIntelEnrichment(ScanSettings s, IReadOnlyList<AnalysisResult> results, TextWriter stderr)
        {
            var providers = new List<IIntelProvider>();
            if (!string.IsNullOrEmpty(s.LocalTiFile) && System.IO.File.Exists(s.LocalTiFile))
            {
                var lti = new LocalThreatIntelProvider(s.LocalTiFile);
                providers.Add(lti);
                stderr.WriteLine($"intel: local-ti loaded {lti.LoadedSha256} sha256, {lti.LoadedUrls} urls, "
                                + $"{lti.LoadedIps} ips, {lti.LoadedDomains} domains from {s.LocalTiFile}");
            }
            if (s.EnableThreatFox) providers.Add(new ThreatFoxProvider());
            var otxKey = s.OtxApiKey ?? Environment.GetEnvironmentVariable("OTX_API_KEY");
            if (!string.IsNullOrEmpty(otxKey)) providers.Add(new OtxProvider(otxKey));

            // Read PCAP first so the IOCs are part of the indicator set.
            PcapReader.PcapIndicators? pcap = null;
            if (!string.IsNullOrEmpty(s.PcapFile) && System.IO.File.Exists(s.PcapFile))
            {
                try
                {
                    pcap = PcapReader.Read(s.PcapFile);
                    stderr.WriteLine($"intel: pcap parsed {pcap.PacketCount} packets, "
                                    + $"{pcap.Ipv4.Count} ips, {pcap.Domains.Count} domains");
                }
                catch (Exception ex) { stderr.WriteLine("intel: pcap read failed: " + ex.Message); }
            }

            if (providers.Count == 0 && pcap == null) return;

            // Attach PCAP IOCs to every result so report writers can surface them.
            if (pcap != null)
            {
                foreach (var r in results)
                {
                    foreach (var ip in pcap.Ipv4)     r.PcapIpHits.Add(ip);
                    foreach (var d  in pcap.Domains)  r.PcapDomainHits.Add(d);
                }
            }
            if (providers.Count == 0) return;

            IntelCache? cache = !string.IsNullOrEmpty(s.IntelCachePath)
                ? new IntelCache(s.IntelCachePath)
                : null;
            var orch = new IntelOrchestrator(providers, cache);

            // Collect a unique IOC set across all results.
            var indicators = new List<IntelIndicator>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            void Add(IndicatorKind k, string v)
            {
                if (string.IsNullOrWhiteSpace(v)) return;
                var key = ((int)k) + ":" + v.ToLowerInvariant();
                if (seen.Add(key)) indicators.Add(new IntelIndicator(k, v));
            }
            foreach (var r in results)
            {
                if (!string.IsNullOrEmpty(r.Sha256) && r.Sha256.Length == 64) Add(IndicatorKind.FileSha256, r.Sha256);
                foreach (var u in r.UrlsFound)   Add(IndicatorKind.Url,    u);
                foreach (var ip in r.Ipv4Hits)   Add(IndicatorKind.Ipv4,   ip);
                foreach (var ip in r.PcapIpHits) Add(IndicatorKind.Ipv4,   ip);
                foreach (var d  in r.PcapDomainHits) Add(IndicatorKind.Domain, d);
            }
            if (indicators.Count == 0) return;

            using var cts = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(30));
            List<IntelLookupResult> lookups;
            try { lookups = orch.LookupAsync(indicators, cts.Token).GetAwaiter().GetResult(); }
            catch (Exception ex) { stderr.WriteLine("intel: lookup failed: " + ex.Message); return; }

            // Fan results back out — every per-IOC verdict is attached to every
            // result that actually contains the indicator, keyed by
            // "<provider>|<kind>:<value>".
            foreach (var look in lookups)
            {
                string key = $"{look.Provider}|{(int)look.Kind}:{look.Indicator.ToLowerInvariant()}";
                foreach (var r in results)
                {
                    bool contains = look.Kind switch
                    {
                        IndicatorKind.FileSha256 => string.Equals(r.Sha256, look.Indicator, StringComparison.OrdinalIgnoreCase),
                        IndicatorKind.Url        => r.UrlsFound.Contains(look.Indicator),
                        IndicatorKind.Ipv4       => r.Ipv4Hits.Contains(look.Indicator) || r.PcapIpHits.Contains(look.Indicator),
                        IndicatorKind.Domain     => r.PcapDomainHits.Contains(look.Indicator),
                        _                        => false,
                    };
                    if (contains) r.IntelLookups[key] = look;
                }
            }

            cache?.Persist();
            int mal = lookups.Count(l => l.Verdict == IntelVerdict.Malicious);
            int sus = lookups.Count(l => l.Verdict == IntelVerdict.Suspicious);
            stderr.WriteLine($"intel: {lookups.Count} lookups across {providers.Count} provider(s) "
                            + $"({mal} malicious, {sus} suspicious)");
        }

        internal static void PushIntegrations(ScanSettings s, IReadOnlyList<AnalysisResult> results, TextWriter stderr)
        {
            if (results.Count == 0) return;

            string? splunkTok = s.SplunkHecToken
                ?? Environment.GetEnvironmentVariable("SPLUNK_HEC_TOKEN");
            if (!string.IsNullOrWhiteSpace(s.SplunkHecUrl) && !string.IsNullOrWhiteSpace(splunkTok))
            {
                try
                {
                    var code = ReportsV2.PushToSplunkAsync(s.SplunkHecUrl, splunkTok, results)
                                        .GetAwaiter().GetResult();
                    stderr.WriteLine($"splunk-hec: {(int)code} {code}");
                }
                catch (Exception ex) { stderr.WriteLine("splunk-hec push failed: " + ex.Message); }
            }

            if (!string.IsNullOrWhiteSpace(s.WebhookUrl))
            {
                try
                {
                    var code = ReportsV2.PostToWebhookAsync(s.WebhookUrl, results)
                                        .GetAwaiter().GetResult();
                    stderr.WriteLine($"webhook ({ReportsV2.DetectWebhookKind(s.WebhookUrl)}): {(int)code} {code}");
                }
                catch (Exception ex) { stderr.WriteLine("webhook push failed: " + ex.Message); }
            }

            string? jiraEmail   = s.JiraEmail   ?? Environment.GetEnvironmentVariable("JIRA_EMAIL");
            string? jiraToken   = s.JiraToken   ?? Environment.GetEnvironmentVariable("JIRA_TOKEN");
            string? jiraProject = s.JiraProject ?? Environment.GetEnvironmentVariable("JIRA_PROJECT");
            if (!string.IsNullOrWhiteSpace(s.JiraUrl)
                && !string.IsNullOrWhiteSpace(jiraEmail)
                && !string.IsNullOrWhiteSpace(jiraToken)
                && !string.IsNullOrWhiteSpace(jiraProject))
            {
                int posted = 0, failed = 0;
                foreach (var r in results.Where(r => r.RiskScore >= 70))
                {
                    try
                    {
                        var code = ReportsV2.PostToJiraAsync(
                            s.JiraUrl, jiraEmail, jiraToken, r, jiraProject)
                            .GetAwaiter().GetResult();
                        if ((int)code is >= 200 and < 300) posted++; else failed++;
                    }
                    catch { failed++; }
                }
                stderr.WriteLine($"jira: posted={posted} failed={failed}");
            }
        }

        public static CommandApp Build()
        {
            var app = new CommandApp();
            app.Configure(c =>
            {
                c.SetApplicationName("antistealer");
                c.PropagateExceptions();

                c.AddCommand<ScanCommand>("scan")
                    .WithDescription("Static analysis of a file or directory.");
                c.AddCommand<CiScanCommand>("ci-scan")
                    .WithDescription("CI-friendly scan with --threshold / --fail-on policy.");
                c.AddCommand<DiffCommand>("diff")
                    .WithDescription("Diff two JSON scan reports (added / removed / score-changed).");
                c.AddCommand<WatchCommand>("watch")
                    .WithDescription("Watch a folder and rescan on file changes.");
                c.AddCommand<VersionCommand>("version")
                    .WithDescription("Print version info (use --json for machine-readable).");
                c.AddCommand<CompletionCommand>("completion")
                    .WithDescription("Print shell completion script (bash|zsh|powershell).");

                c.AddBranch("rules", b =>
                {
                    b.SetDescription("Manage detection rule packs.");
                    b.AddCommand<RulesUpdateCommand>("update")
                        .WithDescription("Pull or copy rule packs into the local rules dir.");
                });
                c.AddBranch("cache", b =>
                {
                    b.SetDescription("Manage the local result cache.");
                    b.AddCommand<CacheClearCommand>("clear")
                        .WithDescription("Remove every file under the cache directory.");
                });
                c.AddBranch("license", b =>
                {
                    b.SetDescription("License operations.");
                    b.AddCommand<LicenseVerifyCommand>("verify")
                        .WithDescription("Verify a license file's signature.");
                });
                c.AddBranch("update", b =>
                {
                    b.SetDescription("Self-update operations.");
                    b.AddCommand<UpdateCheckCommand>("check")
                        .WithDescription("Check a release manifest for a newer version.");
                });
            });
            return app;
        }

        public static int Run(string[] args)
        {
            try { AttachConsole(-1); } catch { /* best-effort; fine under dotnet-host */ }
            try
            {
                return Build().Run(args);
            }
            catch (CommandParseException ex)
            {
                Console.Error.WriteLine(ex.Message);
                return CliExitCodes.Error;
            }
            catch (CommandRuntimeException ex)
            {
                Console.Error.WriteLine(ex.Message);
                return CliExitCodes.Error;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("antistealer: " + ex.Message);
                return CliExitCodes.Error;
            }
        }

        // Same trick the legacy `Cli` uses: WinExe doesn't allocate a console,
        // so we attach to the parent cmd/PowerShell window for visible output.
        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        private static extern bool AttachConsole(int dwProcessId);
    }
}
