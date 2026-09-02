// AA4: default IAntiStealerEngine implementation. A thin orchestrator on top
// of Analyzer.* (the legacy static API). All scoring / detection / cloud
// enrichment lives in Analyzer; this class is responsible only for:
//   * path-walking (directories, recursive vs. single-level)
//   * size / extension gating
//   * progress reporting (IProgress<ScanProgress>)
//   * cancellation honouring (CancellationToken at every file boundary)
//   * optional post-scan cloud enrichment
//   * optional low-risk filtering
// This is the only place outside the WinForms host that knows how to drive
// the analyzer end-to-end, so a CLI / REST service / Avalonia port can be
// built on top of the same code.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using AntiStealerOneExe;

namespace AntiStealer.Engine
{
    internal sealed class DefaultEngine : IAntiStealerEngine
    {
        // AA4: matches AntiStealerOneExe.MainForm.SupportedBinaryExts. Duplicated
        // here (not exposed publicly) so the engine doesn't depend on the GUI.
        // Kept in sync by `EngineSupportedExtensionsAreInSyncWithMainForm` in
        // AntiStealer.Tests.
        internal static readonly HashSet<string> DefaultSupportedExtensions
            = new(StringComparer.OrdinalIgnoreCase)
        {
            // PE-ish.
            ".asi", ".dll", ".exe", ".sys", ".ocx", ".cpl", ".scr",
            // Installers / packages.
            ".msi", ".msix", ".appx",
            // Archives we don't crack yet (still classified + string-scanned).
            ".7z", ".rar", ".gz", ".tar",
            // Non-Windows native.
            ".so", ".dylib",
            // Scripts.
            ".hta", ".js", ".vbs", ".ps1", ".psm1", ".bat", ".cmd", ".lua",
            // Documents.
            ".pdf", ".doc", ".xls", ".ppt", ".docx", ".xlsx", ".pptx", ".rtf",
        };

        private readonly EngineOptions _options;
        private readonly AnalyzerUiSettings _settings;

        public string Version { get; }

        public DefaultEngine(EngineOptions options)
        {
            _options  = options;
            _settings = options.AdvancedSettings ?? new AnalyzerUiSettings();

            // Project the simple knobs onto the underlying analyzer settings so
            // a caller that doesn't pass an AdvancedSettings instance still
            // gets correct behaviour.
            if (options.AdvancedSettings is null)
            {
                _settings.MaxInputFileSizeMb = options.MaxInputFileSizeMb;
                _settings.HideLowRisk        = options.HideLowRisk;
                if (options.MaxParallelism > 0) _settings.MaxParallelism = options.MaxParallelism;
            }

            Version = typeof(DefaultEngine).Assembly
                          .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                      ?? typeof(DefaultEngine).Assembly.GetName().Version?.ToString()
                      ?? "0.0.0";
        }

        public AnalysisResult AnalyzeFile(string path, string? displayPath = null)
            => Analyzer.Analyze(path, displayPath);

        public async Task<AnalysisResult> AnalyzeFileAsync(
            string path,
            string? displayPath = null,
            bool enrichWithCloud = false,
            CancellationToken ct = default)
        {
            AnalysisResult res;
            try
            {
                res = await Task.Run(() => Analyzer.Analyze(path, displayPath), ct);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                res = AnalysisResult.Error(displayPath ?? path, ex.Message);
            }

            if (enrichWithCloud)
            {
                try { await Analyzer.EnrichWithCloudAsync(res, _settings, ct); } catch { }
                try { res.RiskScore = Analyzer.ScorePublic(res); res.FinalizeFlags(); } catch { }
            }

            return res;
        }

        public async Task<ScanResult> ScanAsync(
            ScanRequest request,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            ArgumentNullException.ThrowIfNull(request);

            var sw       = Stopwatch.StartNew();
            var results  = new List<AnalysisResult>();
            int scanned  = 0;
            int skipped  = 0;

            // Phase 1 — enumeration. Resolved up-front so progress can be
            // reported as a percentage; on huge trees the consumer still sees
            // "enumerating" ticks via the first progress callback.
            progress?.Report(new ScanProgress
            {
                FilesScanned = 0,
                FilesTotal   = -1,
                CurrentFile  = "",
                Phase        = "enumerating",
            });

            var (files, enumSkipped) = EnumerateFiles(request, ct);
            skipped += enumSkipped;

            int total = files.Count;
            var allowlist = new HashSet<string>(
                request.AllowlistHashes ?? Array.Empty<string>(),
                StringComparer.OrdinalIgnoreCase);

            // Phase 2 — per-file analysis. Serial walk; each file is still
            // offloaded to a thread-pool task so a synchronous Analyzer.Analyze
            // call doesn't block the calling thread.
            foreach (var (path, displayPath) in files)
            {
                ct.ThrowIfCancellationRequested();

                long fileLen;
                try { fileLen = new FileInfo(path).Length; }
                catch (Exception ex)
                {
                    var err = AnalysisResult.Error(displayPath, $"stat error: {ex.Message}");
                    results.Add(err);
                    skipped++;
                    progress?.Report(BuildTick(scanned, total, displayPath, "scanning", err));
                    continue;
                }

                if (fileLen > _settings.MaxInputFileSizeMb * 1024L * 1024L)
                {
                    var err = AnalysisResult.Error(displayPath,
                        $"Skipped: file larger than {_settings.MaxInputFileSizeMb} MB");
                    results.Add(err);
                    skipped++;
                    progress?.Report(BuildTick(scanned, total, displayPath, "scanning", err));
                    continue;
                }

                AnalysisResult res = await AnalyzeFileAsync(
                    path,
                    displayPath,
                    enrichWithCloud: _options.EnableCloudEnrichment,
                    ct: ct);

                if (allowlist.Count > 0 && !string.IsNullOrEmpty(res.Sha256)
                    && allowlist.Contains(res.Sha256))
                {
                    skipped++;
                    scanned++;
                    progress?.Report(BuildTick(scanned, total, displayPath, "scanning", res));
                    continue;
                }

                scanned++;

                if (_settings.HideLowRisk && res.RiskScore < 40)
                {
                    // Counted as scanned (we did the work) but omitted from the
                    // returned set — matches the WinForms hide-low-risk filter.
                    progress?.Report(BuildTick(scanned, total, displayPath, "scanning", res));
                    continue;
                }

                results.Add(res);
                progress?.Report(BuildTick(scanned, total, displayPath, "scanning", res));
            }

            sw.Stop();

            progress?.Report(new ScanProgress
            {
                FilesScanned = scanned,
                FilesTotal   = total,
                CurrentFile  = "",
                Phase        = "done",
            });

            return new ScanResult
            {
                Files         = results,
                FilesScanned  = scanned,
                FilesSkipped  = skipped,
                Duration      = sw.Elapsed,
                EngineVersion = Version,
            };
        }

        private static ScanProgress BuildTick(
            int scanned, int total, string current, string phase, AnalysisResult? last)
            => new()
            {
                FilesScanned = scanned,
                FilesTotal   = total,
                CurrentFile  = current,
                Phase        = phase,
                LastResult   = last,
            };

        // Resolves ScanRequest.Paths into a concrete (absolutePath, displayPath)
        // list, expanding directories per Recursive and filtering by extension.
        // Returns the count of inputs that we deliberately ignored (e.g. an
        // unsupported extension or a missing path) so the caller can surface a
        // "skipped" count.
        internal (List<(string Path, string Display)> Files, int Skipped) EnumerateFiles(
            ScanRequest request, CancellationToken ct)
        {
            var extensions = request.FileExtensions is { Count: > 0 }
                ? new HashSet<string>(request.FileExtensions, StringComparer.OrdinalIgnoreCase)
                : DefaultSupportedExtensions;

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var work = new List<(string Path, string Display)>();
            int skipped = 0;

            foreach (var inputRaw in request.Paths ?? (IReadOnlyList<string>)Array.Empty<string>())
            {
                ct.ThrowIfCancellationRequested();
                if (string.IsNullOrWhiteSpace(inputRaw)) { skipped++; continue; }

                var input = inputRaw;

                if (Directory.Exists(input))
                {
                    var so = request.Recursive
                        ? SearchOption.AllDirectories
                        : SearchOption.TopDirectoryOnly;
                    IEnumerable<string> entries;
                    try { entries = Directory.EnumerateFiles(input, "*", so); }
                    catch { skipped++; continue; }

                    foreach (var f in entries)
                    {
                        ct.ThrowIfCancellationRequested();
                        var ext = Path.GetExtension(f);
                        if (!extensions.Contains(ext)) { skipped++; continue; }
                        var full = SafeFullPath(f);
                        if (full is null) { skipped++; continue; }
                        if (!seen.Add(full)) continue;
                        work.Add((full, f));
                    }
                }
                else if (File.Exists(input))
                {
                    var ext = Path.GetExtension(input);
                    if (!extensions.Contains(ext)) { skipped++; continue; }
                    var full = SafeFullPath(input);
                    if (full is null) { skipped++; continue; }
                    if (!seen.Add(full)) continue;
                    work.Add((full, input));
                }
                else
                {
                    skipped++;
                }
            }

            return (work, skipped);
        }

        private static string? SafeFullPath(string p)
        {
            try { return Path.GetFullPath(p); }
            catch { return null; }
        }
    }
}
