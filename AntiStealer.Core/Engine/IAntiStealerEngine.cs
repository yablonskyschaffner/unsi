// AA4: public engine facade. Lives in the dedicated AntiStealer.Engine namespace
// so external consumers (the WinForms GUI, a future CLI / REST service / Avalonia
// port) have a single, stable, UI-free entry point into the scanner.
//
// The implementation (DefaultEngine) is a thin wrapper around the legacy
// Analyzer.* static API so backward compatibility with serialised reports
// and the 656 existing unit tests is preserved verbatim. The namespace split
// is intentional: AntiStealerOneExe.* hosts the legacy types that ship in
// JSON reports; AntiStealer.Engine.* hosts the new, hand-curated public API.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AntiStealerOneExe;

namespace AntiStealer.Engine
{
    /// <summary>
    /// Public facade for the antistealer scanner. Implementations are obtained
    /// through <see cref="AntiStealerEngineFactory.Create"/>.
    /// </summary>
    public interface IAntiStealerEngine
    {
        /// <summary>Engine version surfaced for logs / reports.</summary>
        string Version { get; }

        /// <summary>
        /// Synchronous single-file analysis. Useful for tests, batch tools,
        /// and any caller that already has its own concurrency strategy.
        /// </summary>
        AnalysisResult AnalyzeFile(string path, string? displayPath = null);

        /// <summary>
        /// Asynchronous single-file analysis with optional cloud enrichment.
        /// When <paramref name="enrichWithCloud"/> is true the engine runs the
        /// configured VirusTotal / Triage / ClamAV / etc. lookups (gated by
        /// the API keys in <see cref="EngineOptions.AdvancedSettings"/>) and
        /// re-scores the result before returning it. Honours
        /// <paramref name="ct"/>.
        /// </summary>
        Task<AnalysisResult> AnalyzeFileAsync(
            string path,
            string? displayPath = null,
            bool enrichWithCloud = false,
            CancellationToken ct = default);

        /// <summary>
        /// Asynchronously scan a set of files / directories described by
        /// <paramref name="request"/>. Progress is reported through
        /// <paramref name="progress"/> (post per-file plus an "enumerating"
        /// phase up-front). <paramref name="ct"/> is honoured at every file
        /// boundary.
        /// </summary>
        Task<ScanResult> ScanAsync(
            ScanRequest request,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default);
    }

    /// <summary>
    /// Per-scan input: which paths to walk and how aggressively. Decoupled
    /// from <see cref="EngineOptions"/> so a long-lived engine instance can
    /// service many requests with different paths / recursion preferences.
    /// </summary>
    public sealed class ScanRequest
    {
        public IReadOnlyList<string> Paths { get; init; } = Array.Empty<string>();

        /// <summary>When a path is a directory, recurse into subdirectories.</summary>
        public bool Recursive { get; init; } = true;

        /// <summary>
        /// Optional extension allow-list (with leading dot, lower-case, e.g. ".exe").
        /// When null the engine uses its built-in supported binary set.
        /// </summary>
        public IReadOnlyCollection<string>? FileExtensions { get; init; }

        /// <summary>
        /// Optional hashes (lower-case sha256) to skip — useful when the host
        /// already has a verdict for a file and only wants the engine to scan
        /// the rest.
        /// </summary>
        public IReadOnlyCollection<string> AllowlistHashes { get; init; } = Array.Empty<string>();
    }

    /// <summary>
    /// Aggregated scan result. Files are returned in completion order.
    /// </summary>
    public sealed class ScanResult
    {
        public IReadOnlyList<AnalysisResult> Files  { get; init; } = Array.Empty<AnalysisResult>();
        public int                            FilesScanned { get; init; }
        public int                            FilesSkipped { get; init; }
        public TimeSpan                       Duration     { get; init; }
        public string                         EngineVersion { get; init; } = "";
    }

    /// <summary>
    /// One progress tick. Hosts (WinForms / CLI / service) translate these into
    /// UI-specific updates. Carries the latest per-file <see cref="AnalysisResult"/>
    /// so tables can be populated incrementally.
    /// </summary>
    public sealed class ScanProgress
    {
        public int             FilesScanned { get; init; }
        public int             FilesTotal   { get; init; }   // -1 = enumeration not yet finished
        public string          CurrentFile  { get; init; } = "";
        public string          Phase        { get; init; } = "scanning"; // "enumerating" | "scanning" | "enriching" | "done"
        public AnalysisResult? LastResult   { get; init; }

        public int Percent => FilesTotal > 0
            ? (int)Math.Round(100.0 * FilesScanned / FilesTotal)
            : 0;
    }

    /// <summary>
    /// Long-lived engine configuration (cloud knobs, scan limits, advanced
    /// settings escape-hatch). Construct once, reuse across many
    /// <see cref="IAntiStealerEngine.ScanAsync"/> calls.
    /// </summary>
    public sealed class EngineOptions
    {
        /// <summary>Files above this size are recorded as skipped instead of analysed.</summary>
        public int MaxInputFileSizeMb { get; init; } = 64;

        /// <summary>When true, files with RiskScore &lt; 40 are omitted from <see cref="ScanResult.Files"/>.</summary>
        public bool HideLowRisk { get; init; }

        /// <summary>
        /// Maximum concurrent file analyses. 0 = use Environment.ProcessorCount.
        /// </summary>
        public int MaxParallelism { get; init; }

        /// <summary>
        /// When true the engine performs the cloud-enrichment pass on every
        /// result (VirusTotal / Triage / etc.) — gated independently by the
        /// individual API keys in <see cref="AdvancedSettings"/>.
        /// </summary>
        public bool EnableCloudEnrichment { get; init; }

        /// <summary>
        /// Escape-hatch for callers that need fine-grained control over the
        /// underlying analyzer (cloud API keys, parser limits, etc.). When
        /// null, the engine builds a fresh <see cref="AnalyzerUiSettings"/>
        /// instance and projects the simpler EngineOptions fields into it.
        /// </summary>
        public AnalyzerUiSettings? AdvancedSettings { get; init; }
    }
}
