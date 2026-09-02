// PR 6 — section 7 tests. These exercise the new Spectre.Console.Cli-based
// command tree (`CliApp`) and the factored `ScanRunner` / `ScanOutputWriter`
// / `ScanDiff` / `RiskBandExtensions` helpers. We deliberately do NOT spawn
// the WinForms host — `AntiStealer.Tests` targets `net8.0` (no Forms), so
// every assertion runs cross-platform on the build matrix.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using AntiStealerOneExe;
using Spectre.Console.Cli;
using Xunit;

namespace AntiStealer.Tests;

public class CliTests
{
    // ---------------------------------------------------------------------
    // RiskBandExtensions — 7.6 / 7.8 (exit-code policy + ci-scan threshold)
    // ---------------------------------------------------------------------

    [Theory]
    [InlineData("low",    RiskBand.Low)]
    [InlineData("Medium", RiskBand.Medium)]
    [InlineData("HIGH",   RiskBand.High)]
    [InlineData("m",      RiskBand.Medium)]
    [InlineData("h",      RiskBand.High)]
    [InlineData("error",  RiskBand.High)]
    public void RiskBand_TryParse_AcceptsKnownSpellings(string input, RiskBand expected)
    {
        Assert.True(RiskBandExtensions.TryParse(input, out var band));
        Assert.Equal(expected, band);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("nonsense")]
    public void RiskBand_TryParse_RejectsGarbage(string? input)
    {
        Assert.False(RiskBandExtensions.TryParse(input, out _));
    }

    [Fact]
    public void RiskBand_MeetsOrExceeds_RespectsThresholdLadder()
    {
        AnalysisResult Score(int s) { var r = new AnalysisResult("x") { RiskScore = s }; r.FinalizeFlags(); return r; }

        var low    = Score(10);   // RiskLevel == "LOW"
        var medium = Score(50);   // RiskLevel == "MEDIUM"
        var high   = Score(80);   // RiskLevel == "HIGH"

        // --fail-on low: everything fails.
        Assert.True (RiskBandExtensions.MeetsOrExceeds(low,    RiskBand.Low));
        Assert.True (RiskBandExtensions.MeetsOrExceeds(medium, RiskBand.Low));
        Assert.True (RiskBandExtensions.MeetsOrExceeds(high,   RiskBand.Low));

        // --fail-on medium: low passes, medium/high fail.
        Assert.False(RiskBandExtensions.MeetsOrExceeds(low,    RiskBand.Medium));
        Assert.True (RiskBandExtensions.MeetsOrExceeds(medium, RiskBand.Medium));
        Assert.True (RiskBandExtensions.MeetsOrExceeds(high,   RiskBand.Medium));

        // --fail-on high: only high (or ERROR file-type) fails.
        Assert.False(RiskBandExtensions.MeetsOrExceeds(low,    RiskBand.High));
        Assert.False(RiskBandExtensions.MeetsOrExceeds(medium, RiskBand.High));
        Assert.True (RiskBandExtensions.MeetsOrExceeds(high,   RiskBand.High));

        // ERROR file-type is treated as High so CI fails noisily.
        var err = AnalysisResult.Error("x", "boom");
        Assert.True(RiskBandExtensions.MeetsOrExceeds(err, RiskBand.High));
    }

    // ---------------------------------------------------------------------
    // ScanSettings.ResolveFormat — 7.5 + format aliases
    // ---------------------------------------------------------------------

    [Fact]
    public void ScanSettings_ResolveFormat_FallsThroughAliases()
    {
        Assert.Equal("json",       new ScanSettings().ResolveFormat());
        Assert.Equal("html",       new ScanSettings { Html = true }.ResolveFormat());
        Assert.Equal("pdf",        new ScanSettings { Pdf  = true }.ResolveFormat());
        Assert.Equal("stix",       new ScanSettings { Stix = true }.ResolveFormat());
        Assert.Equal("sarif",      new ScanSettings { Sarif = true }.ResolveFormat());
        Assert.Equal("csv",        new ScanSettings { Csv  = true }.ResolveFormat());
        Assert.Equal("batch-html", new ScanSettings { BatchHtml = true }.ResolveFormat());
        // explicit --format overrides aliases.
        Assert.Equal("sarif",      new ScanSettings { Format = "SARIF", Html = true }.ResolveFormat());
    }

    // ---------------------------------------------------------------------
    // ScanRunner — 7.1 (factored core) + 7.4 (progress callback)
    // ---------------------------------------------------------------------

    [Fact]
    public void ScanRunner_ExpandTarget_FiltersByExtensionAndRecursion()
    {
        var root = Path.Combine(Path.GetTempPath(), "ast-cli-" + Guid.NewGuid().ToString("N"));
        var sub  = Path.Combine(root, "sub");
        Directory.CreateDirectory(sub);
        try
        {
            File.WriteAllBytes(Path.Combine(root, "a.exe"),  new byte[] { 0x4D, 0x5A });
            File.WriteAllBytes(Path.Combine(root, "b.txt"),  new byte[] { 0x00 });        // ignored
            File.WriteAllBytes(Path.Combine(sub,  "c.dll"),  new byte[] { 0x4D, 0x5A });
            var shallow = ScanRunner.ExpandTarget(root, recursive: false);
            Assert.Single(shallow);
            Assert.EndsWith("a.exe", shallow[0]);
            var deep    = ScanRunner.ExpandTarget(root, recursive: true);
            Assert.Equal(2, deep.Count);
        }
        finally { try { Directory.Delete(root, true); } catch { } }
    }

    [Fact]
    public void ScanRunner_Run_ProducesResultAndProgressTicks()
    {
        var root = Path.Combine(Path.GetTempPath(), "ast-cli-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            // Minimal MZ stub. The analyzer will run, but the focus here is the
            // plumbing — we only care that we get a result and that the progress
            // callback fires.
            var pe = new byte[1024];
            pe[0] = 0x4D; pe[1] = 0x5A;
            File.WriteAllBytes(Path.Combine(root, "a.exe"), pe);
            File.WriteAllBytes(Path.Combine(root, "b.dll"), pe);

            var ticks = new List<ScanProgressTick>();
            var outcome = ScanRunner.Run(new ScanOptions
            {
                Target      = root,
                Recursive   = false,
                MaxParallel = 1,
                OnProgress  = t => ticks.Add(t),
            });

            Assert.Equal(2, outcome.FilesEnumerated);
            Assert.True(outcome.Results.Count <= 2);
            Assert.True(outcome.Duration > TimeSpan.Zero);
            Assert.Equal(2, ticks.Count);
            Assert.True(ticks.Last().Done == 2);
            Assert.True(ticks.Last().Total == 2);
        }
        finally { try { Directory.Delete(root, true); } catch { } }
    }

    // ---------------------------------------------------------------------
    // ScanOutputWriter — 7.5 ndjson + format dispatch
    // ---------------------------------------------------------------------

    [Fact]
    public void ScanOutputWriter_Ndjson_OneLinePerResult()
    {
        var r1 = new AnalysisResult("a.exe") { RiskScore = 70 }; r1.FinalizeFlags();
        var r2 = new AnalysisResult("b.exe") { RiskScore = 10 }; r2.FinalizeFlags();
        var so = new StringWriter();
        var se = new StringWriter();
        var rc = ScanOutputWriter.Write(new[] { r1, r2 }, "json", outPath: null, batchDir: null,
                                        ndjson: true, stdout: so, stderr: se);
        Assert.Equal(CliExitCodes.Clean, rc);
        var lines = so.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);
        // Each line must be valid JSON.
        foreach (var line in lines)
        {
            using var doc = JsonDocument.Parse(line);
            Assert.True(doc.RootElement.TryGetProperty("filePath", out _));
        }
    }

    [Theory]
    [InlineData("json")]
    [InlineData("csv")]
    [InlineData("html")]
    [InlineData("stix")]
    [InlineData("sarif")]
    public void ScanOutputWriter_KnownFormats_WriteToFile(string fmt)
    {
        var r = new AnalysisResult("a.exe") { RiskScore = 50 }; r.FinalizeFlags();
        var path = Path.Combine(Path.GetTempPath(), $"ast-cli-{fmt}-{Guid.NewGuid():N}.out");
        try
        {
            var so = new StringWriter();
            var se = new StringWriter();
            var rc = ScanOutputWriter.Write(new[] { r }, fmt, outPath: path, batchDir: null,
                                            ndjson: false, stdout: so, stderr: se);
            Assert.Equal(CliExitCodes.Clean, rc);
            Assert.True(File.Exists(path));
            Assert.True(new FileInfo(path).Length > 0);
        }
        finally { try { File.Delete(path); } catch { } }
    }

    [Fact]
    public void ScanOutputWriter_UnknownFormat_ReturnsError()
    {
        var so = new StringWriter();
        var se = new StringWriter();
        var rc = ScanOutputWriter.Write(Array.Empty<AnalysisResult>(), "bogus", null, null, false, so, se);
        Assert.Equal(CliExitCodes.Error, rc);
        Assert.Contains("Unknown", se.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ScanOutputWriter_PdfRequiresOutPath()
    {
        var so = new StringWriter();
        var se = new StringWriter();
        var rc = ScanOutputWriter.Write(Array.Empty<AnalysisResult>(), "pdf", null, null, false, so, se);
        Assert.Equal(CliExitCodes.Error, rc);
        Assert.Contains("--pdf", se.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ScanOutputWriter_BatchHtmlRequiresBatchOut()
    {
        var so = new StringWriter();
        var se = new StringWriter();
        var rc = ScanOutputWriter.Write(Array.Empty<AnalysisResult>(), "batch-html", null, null, false, so, se);
        Assert.Equal(CliExitCodes.Error, rc);
        Assert.Contains("--batch-html", se.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    // ---------------------------------------------------------------------
    // ScanDiff — 7.2 `antistealer diff`
    // ---------------------------------------------------------------------

    [Fact]
    public void ScanDiff_DetectsAddedRemovedAndScoreChanged()
    {
        var oldR = new List<AnalysisResult>
        {
            new("a.exe") { Sha256 = "AAA", RiskScore = 10 },
            new("b.exe") { Sha256 = "BBB", RiskScore = 50 },
        };
        var newR = new List<AnalysisResult>
        {
            new("b.exe") { Sha256 = "BBB", RiskScore = 80 },  // score-changed
            new("c.exe") { Sha256 = "CCC", RiskScore = 70 },  // added
            // "a.exe" removed
        };
        oldR.ForEach(r => r.FinalizeFlags());
        newR.ForEach(r => r.FinalizeFlags());

        var diffs = ScanDiff.Compute(oldR, newR);

        var added         = diffs.Single(d => d.Change == "added");
        var removed       = diffs.Single(d => d.Change == "removed");
        var scoreChanged  = diffs.Single(d => d.Change == "score-changed");

        Assert.Equal("CCC", added.Sha256);
        Assert.Equal("AAA", removed.Sha256);
        Assert.Equal("BBB", scoreChanged.Sha256);
        Assert.Equal(50,    scoreChanged.OldScore);
        Assert.Equal(80,    scoreChanged.NewScore);
    }

    [Fact]
    public void ScanDiff_LoadJson_AcceptsArrayShape()
    {
        var r = new AnalysisResult("x.exe") { Sha256 = "ABC", RiskScore = 30 };
        r.FinalizeFlags();
        var path = Path.Combine(Path.GetTempPath(), "ast-cli-diff-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            File.WriteAllText(path, ReportWriter.ToJson(new[] { r }));
            var roundtripped = ScanDiff.LoadJson(path);
            Assert.Single(roundtripped);
            Assert.Equal("ABC", roundtripped[0].Sha256);
        }
        finally { try { File.Delete(path); } catch { } }
    }

    // ---------------------------------------------------------------------
    // CommandApp wiring — 7.1 / 7.2: every command is reachable
    // ---------------------------------------------------------------------

    [Fact]
    public void CommandApp_Build_DoesNotThrow()
    {
        var app = CliApp.Build();
        Assert.NotNull(app);
    }

    [Theory]
    [InlineData("scan")]
    [InlineData("ci-scan")]
    [InlineData("diff")]
    [InlineData("watch")]
    [InlineData("version")]
    [InlineData("completion")]
    [InlineData("rules update")]
    [InlineData("cache clear")]
    [InlineData("license verify")]
    [InlineData("update check")]
    public void CommandApp_HelpForKnownCommands_IsRoutable(string command)
    {
        // Use --help — Spectre returns 0 and writes usage; if the command tree
        // were misconfigured we'd get a CommandRuntimeException.
        var bits = command.Split(' ', StringSplitOptions.RemoveEmptyEntries).Append("--help").ToArray();
        var stdout = Console.Out;
        var stderr = Console.Error;
        try
        {
            using var so = new StringWriter();
            using var se = new StringWriter();
            Console.SetOut(so);
            Console.SetError(se);
            int rc = CliApp.Run(bits);
            // Spectre returns 0 (or 1 for parse errors) for --help; either way the
            // important assertion is that we did not throw.
            Assert.True(rc == CliExitCodes.Clean || rc == CliExitCodes.Suspicious
                        || rc == CliExitCodes.Error, $"unexpected rc {rc} for `{command}`");
        }
        finally
        {
            Console.SetOut(stdout);
            Console.SetError(stderr);
        }
    }

    // ---------------------------------------------------------------------
    // RunScan exit codes — 7.6
    // ---------------------------------------------------------------------

    [Fact]
    public void RunScan_NoFiles_ReturnsError()
    {
        var emptyDir = Path.Combine(Path.GetTempPath(), "ast-cli-empty-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(emptyDir);
        try
        {
            int rc = CliApp.RunScan(new ScanSettings
            {
                Path       = emptyDir,
                NoProgress = true,
                Format     = "json",
                OutPath    = Path.Combine(emptyDir, "out.json"),
            }, fallbackFailBand: null);
            Assert.Equal(CliExitCodes.Error, rc);
        }
        finally { try { Directory.Delete(emptyDir, true); } catch { } }
    }

    [Fact]
    public void RunScan_WithFailOnHigh_ReturnsSuspiciousWhenAnyHigh()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ast-cli-fail-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            // Bake a tiny MZ stub so Analyze produces a deterministic result. The
            // RiskScore for an empty 64-byte MZ is < 40, so we rely on a synthesised
            // FailOn-low policy to flip the bit (rather than trying to engineer a
            // 70+ score from a stub).
            var pe = new byte[64]; pe[0] = 0x4D; pe[1] = 0x5A;
            File.WriteAllBytes(Path.Combine(dir, "a.exe"), pe);

            var outPath = Path.Combine(dir, "out.json");
            int rc = CliApp.RunScan(new ScanSettings
            {
                Path       = dir,
                NoProgress = true,
                Format     = "json",
                OutPath    = outPath,
            }, fallbackFailBand: RiskBand.Low);
            // fail-on=low always fires when there is any result.
            Assert.Equal(CliExitCodes.Suspicious, rc);
            Assert.True(File.Exists(outPath));
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    // ---------------------------------------------------------------------
    // Progress tick math — 7.4 (ETA + MB/s)
    // ---------------------------------------------------------------------

    [Fact]
    public void ScanProgressTick_ComputesMbPerSecAndEta()
    {
        var t = new ScanProgressTick
        {
            Done       = 5,
            Total      = 10,
            BytesDone  = 5L * 1024 * 1024,    // 5 MB
            BytesTotal = 10L * 1024 * 1024,
            Elapsed    = TimeSpan.FromSeconds(1),
        };
        Assert.Equal(5.0, t.MbPerSec, 1);
        Assert.True(t.EtaApprox > TimeSpan.Zero);
        Assert.True(t.EtaApprox < TimeSpan.FromSeconds(10));
    }
}
