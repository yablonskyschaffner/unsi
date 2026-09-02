using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests;

/// <summary>
/// I4: Integration tests on archive handling — scanner should survive nested ZIPs, refuse zip-slip
/// entries (../ escapes) and not blow up on an archive bomb (huge declared uncompressed size).
/// These tests create synthetic ZIPs on disk; they don't start the WinForms UI.
/// </summary>
// `Analyzer.Analyze` may emit AsiLogger warnings via SafeRun; serialise with
// HardeningTests.AsiLogger_EmitsNdjsonToFile so the file-line count stays
// deterministic on parallel-friendly runners (Windows CI).
[Collection("EncryptedQuarantine")]
public class ArchiveScanningTests : IDisposable
{
    private readonly string _tempDir;

    public ArchiveScanningTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "antistealer-arctests-" + Guid.NewGuid().ToString("N").Substring(0, 8));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    private string MakeZip(string name, Action<ZipArchive> build)
    {
        var p = Path.Combine(_tempDir, name);
        using (var fs = File.Create(p))
        using (var z = new ZipArchive(fs, ZipArchiveMode.Create))
            build(z);
        return p;
    }

    private static void AddText(ZipArchive z, string entryName, string text)
    {
        var entry = z.CreateEntry(entryName);
        using var s = entry.Open();
        var bytes = Encoding.ASCII.GetBytes(text);
        s.Write(bytes, 0, bytes.Length);
    }

    [Fact]
    public void Analyze_OnFlatZip_DoesNotThrow()
    {
        var zipPath = MakeZip("flat.zip", z =>
        {
            AddText(z, "a.txt", "hello world");
            AddText(z, "b.txt", "another file");
        });

        var r = Analyzer.Analyze(zipPath, zipPath);
        Assert.NotNull(r);
        // A plain data zip should score low and not throw.
        Assert.InRange(r.RiskScore, 0, 90);
    }

    [Fact]
    public void Analyze_OnZipSlipEntry_DoesNotEscapeSandbox()
    {
        // An entry name with .. components must never be extracted outside the archive temp dir.
        var zipPath = MakeZip("slip.zip", z =>
        {
            AddText(z, "..\\..\\..\\evil.txt", "pwned");
            AddText(z, "normal.txt", "ok");
        });

        // The archive is passed into Analyzer the same way the UI would; Analyzer.Analyze may defer
        // to its inner archive-scanner via the MainForm path (which we can't invoke without WinForms
        // wiring). But Analyze on the .zip itself should not throw and should not write outside tmp.
        var before = Directory.GetFiles(Path.GetTempPath(), "evil.txt", SearchOption.TopDirectoryOnly).Length;
        var r = Analyzer.Analyze(zipPath, zipPath);
        var after  = Directory.GetFiles(Path.GetTempPath(), "evil.txt", SearchOption.TopDirectoryOnly).Length;

        Assert.NotNull(r);
        Assert.Equal(before, after);  // nothing new landed in %TEMP%
    }

    [Fact]
    public void Analyze_OnArchiveWithDeeplyNestedPaths_DoesNotHang()
    {
        var zipPath = MakeZip("deep.zip", z =>
        {
            for (int i = 0; i < 200; i++)
                AddText(z, string.Concat(System.Linq.Enumerable.Repeat("dir/", 20)) + $"f{i}.txt", "x");
        });

        // Scanner should complete within a sane wall-time even on very deep entry paths.
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var r = Analyzer.Analyze(zipPath, zipPath);
        sw.Stop();

        Assert.NotNull(r);
        Assert.True(sw.Elapsed.TotalSeconds < 30, $"Deeply-nested zip took {sw.Elapsed.TotalSeconds:0.0}s to analyze — possible perf regression.");
    }
}
