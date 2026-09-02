using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AntiStealer.Engine;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests;

/// <summary>
/// AA4: contract tests for the public <see cref="IAntiStealerEngine"/> facade.
/// These run alongside the analyzer-level tests but talk only to the public
/// `AntiStealer.Engine.*` surface — i.e. the same API a future CLI / REST /
/// Avalonia consumer would use. They explicitly do NOT poke at
/// `Analyzer.*` to keep the facade contract honest.
/// </summary>
[Collection("EncryptedQuarantine")]
public class EngineFacadeTests : IDisposable
{
    private readonly string _tempDir;

    public EngineFacadeTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(),
            "antistealer-engine-tests-" + Guid.NewGuid().ToString("N").Substring(0, 8));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { /* best-effort */ }
    }

    private string WriteFile(string name, byte[] data)
    {
        var path = Path.Combine(_tempDir, name);
        File.WriteAllBytes(path, data);
        return path;
    }

    [Fact]
    public void Factory_Create_ReturnsFunctionalEngine()
    {
        var engine = AntiStealerEngineFactory.Create();
        Assert.NotNull(engine);
        Assert.False(string.IsNullOrWhiteSpace(engine.Version));
    }

    [Fact]
    public void Factory_Create_AcceptsCustomOptions()
    {
        var engine = AntiStealerEngineFactory.Create(new EngineOptions
        {
            MaxInputFileSizeMb    = 8,
            HideLowRisk           = true,
            EnableCloudEnrichment = false,
        });
        Assert.NotNull(engine);
    }

    [Fact]
    public void AnalyzeFile_RoundTripsAnExistingFile()
    {
        var path = WriteFile("plain.dll", new byte[] { 0x00, 0x00, 0x00 });
        var engine = AntiStealerEngineFactory.Create();

        var res = engine.AnalyzeFile(path, path);

        Assert.NotNull(res);
        // The legacy Analyzer.Analyze returns a fully-populated AnalysisResult
        // regardless of whether the bytes form a real PE; we just assert that
        // the facade hands the result back unmodified.
        Assert.Equal(path, res.FilePath);
    }

    [Fact]
    public async Task AnalyzeFileAsync_HonoursCancellation()
    {
        var path = WriteFile("plain.dll", new byte[] { 0x00, 0x00, 0x00 });
        var engine = AntiStealerEngineFactory.Create();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            engine.AnalyzeFileAsync(path, path, enrichWithCloud: false, ct: cts.Token));
    }

    [Fact]
    public async Task ScanAsync_ReportsProgressForEveryFile()
    {
        var a = WriteFile("a.dll", new byte[] { 0x00 });
        var b = WriteFile("b.dll", new byte[] { 0x00 });
        var c = WriteFile("c.dll", new byte[] { 0x00 });

        var ticks = new List<ScanProgress>();
        var engine = AntiStealerEngineFactory.Create();
        var result = await engine.ScanAsync(
            new ScanRequest { Paths = new[] { a, b, c } },
            new Progress<ScanProgress>(p => { lock (ticks) ticks.Add(p); }),
            CancellationToken.None);

        Assert.Equal(3, result.Files.Count);
        Assert.Equal(3, result.FilesScanned);

        // Give the synchronisation context a moment to drain the Progress
        // posts — Progress<T> hops through the captured SC asynchronously.
        await Task.Delay(50);

        List<ScanProgress> snapshot;
        lock (ticks) snapshot = new List<ScanProgress>(ticks);

        Assert.Contains(snapshot, t => t.Phase == "enumerating");
        Assert.Contains(snapshot, t => t.Phase == "done");
        Assert.Contains(snapshot, t => t.LastResult is not null);
    }

    [Fact]
    public async Task ScanAsync_HonoursCancellationBetweenFiles()
    {
        // Write 5 files; cancel from the progress callback after the first.
        var files = Enumerable.Range(0, 5)
            .Select(i => WriteFile($"x{i}.dll", new byte[] { 0x00 }))
            .ToArray();

        using var cts = new CancellationTokenSource();
        var engine = AntiStealerEngineFactory.Create();
        var progress = new Progress<ScanProgress>(p =>
        {
            if (p.FilesScanned >= 1) cts.Cancel();
        });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            engine.ScanAsync(
                new ScanRequest { Paths = files },
                progress,
                cts.Token));
    }

    [Fact]
    public async Task ScanAsync_RecursesIntoDirectoriesWhenRequested()
    {
        var sub = Path.Combine(_tempDir, "nested");
        Directory.CreateDirectory(sub);
        WriteFile(Path.Combine("nested", "x.dll"), new byte[] { 0x00 });
        WriteFile(Path.Combine("nested", "y.dll"), new byte[] { 0x00 });

        var engine = AntiStealerEngineFactory.Create();
        var recursive = await engine.ScanAsync(
            new ScanRequest { Paths = new[] { _tempDir }, Recursive = true });

        Assert.Equal(2, recursive.FilesScanned);
        Assert.Equal(2, recursive.Files.Count);
    }

    [Fact]
    public async Task ScanAsync_NonRecursiveIgnoresNestedFiles()
    {
        var sub = Path.Combine(_tempDir, "nested");
        Directory.CreateDirectory(sub);
        WriteFile(Path.Combine("nested", "x.dll"), new byte[] { 0x00 });

        var engine = AntiStealerEngineFactory.Create();
        var flat = await engine.ScanAsync(
            new ScanRequest { Paths = new[] { _tempDir }, Recursive = false });

        Assert.Equal(0, flat.FilesScanned);
    }

    [Fact]
    public async Task ScanAsync_FiltersByExtension()
    {
        WriteFile("keep.dll", new byte[] { 0x00 });
        WriteFile("skip.txt", new byte[] { 0x00 }); // not in default supported set

        var engine = AntiStealerEngineFactory.Create();
        var result = await engine.ScanAsync(
            new ScanRequest { Paths = new[] { _tempDir } });

        Assert.Equal(1, result.FilesScanned);
        Assert.Single(result.Files);
        Assert.EndsWith(".dll", result.Files[0].FilePath);
    }

    [Fact]
    public async Task ScanAsync_RespectsCustomExtensionAllowlist()
    {
        WriteFile("foo.weird", new byte[] { 0x00 });

        var engine = AntiStealerEngineFactory.Create();
        var result = await engine.ScanAsync(new ScanRequest
        {
            Paths          = new[] { _tempDir },
            FileExtensions = new[] { ".weird" },
        });

        Assert.Equal(1, result.FilesScanned);
        Assert.EndsWith(".weird", result.Files[0].FilePath);
    }

    [Fact]
    public async Task ScanAsync_SkipsFilesAboveSizeLimit()
    {
        // Build a 2 MB file then cap engine at 1 MB.
        var big = WriteFile("big.dll", new byte[2 * 1024 * 1024]);

        var engine = AntiStealerEngineFactory.Create(new EngineOptions
        {
            MaxInputFileSizeMb = 1,
        });
        var result = await engine.ScanAsync(
            new ScanRequest { Paths = new[] { big } });

        // Skipped files are reported as Error rows in the result set, so the
        // facade contract is: 1 entry, 1 skipped, "larger than 1 MB" reason.
        Assert.Single(result.Files);
        Assert.True(result.FilesSkipped >= 1);
        Assert.Equal("ERROR", result.Files[0].FileType);
        Assert.Contains("larger than 1 MB", result.Files[0].ReasonsShort ?? "");
    }

    [Fact]
    public async Task ScanAsync_RespectsHashAllowlist()
    {
        var a = WriteFile("a.dll", new byte[] { 0x00 });
        var b = WriteFile("b.dll", new byte[] { 0x01 });

        var engine = AntiStealerEngineFactory.Create();
        // First scan: discover both files and read sha256s.
        var probe = await engine.ScanAsync(
            new ScanRequest { Paths = new[] { a, b } });
        Assert.Equal(2, probe.Files.Count);

        var skipHash = probe.Files[0].Sha256;
        Assert.False(string.IsNullOrEmpty(skipHash));

        var withAllowlist = await engine.ScanAsync(new ScanRequest
        {
            Paths            = new[] { a, b },
            AllowlistHashes  = new[] { skipHash },
        });

        Assert.Equal(2, withAllowlist.FilesScanned); // both analysed
        Assert.True(withAllowlist.FilesSkipped >= 1);
        Assert.DoesNotContain(withAllowlist.Files, f => f.Sha256 == skipHash);
    }

    [Fact]
    public async Task ScanAsync_RecordsEngineVersionAndDuration()
    {
        var path = WriteFile("a.dll", new byte[] { 0x00 });
        var engine = AntiStealerEngineFactory.Create();
        var result = await engine.ScanAsync(new ScanRequest { Paths = new[] { path } });

        Assert.False(string.IsNullOrWhiteSpace(result.EngineVersion));
        Assert.True(result.Duration >= TimeSpan.Zero);
    }

    [Fact]
    public async Task ScanAsync_EmptyRequest_ReturnsEmptyResult()
    {
        var engine = AntiStealerEngineFactory.Create();
        var result = await engine.ScanAsync(new ScanRequest { Paths = Array.Empty<string>() });
        Assert.Empty(result.Files);
        Assert.Equal(0, result.FilesScanned);
    }

    [Fact]
    public async Task ScanAsync_NullRequest_Throws()
    {
        var engine = AntiStealerEngineFactory.Create();
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            engine.ScanAsync(null!));
    }
}
