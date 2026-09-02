using System;
using System.Diagnostics;
using System.IO;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests;

/// <summary>
/// Section 6.6 — Lightweight fuzzing harness for <see cref="Analyzer.Analyze"/>.
///
/// We don't pull in SharpFuzz/libFuzzer-DotNet (would require a separate harness
/// project + native deps). Instead, we feed the analyzer a deterministic mix of
/// random byte streams, malformed PE headers, truncated archives, and other
/// edge-case payloads. The contract under test is:
///
///   * Analyzer.Analyze never throws on arbitrary bytes (only swallowed
///     SafeRun-warnings should escape).
///   * It returns a non-null <see cref="AnalysisResult"/> with a valid
///     RiskScore (0-100) and RiskLevel within seconds.
///
/// Random seed is fixed so failures are reproducible. We share a temp dir per
/// test class so concurrent fuzz runs don't fight over disk.
/// </summary>
// `Analyzer.Analyze` may emit AsiLogger warnings via SafeRun; serialise with
// HardeningTests.AsiLogger_EmitsNdjsonToFile so the file-line count stays
// deterministic on parallel-friendly runners (Windows CI).
[Collection("EncryptedQuarantine")]
public class AnalyzerFuzzTests : IDisposable
{
    private readonly string _tempDir;

    public AnalyzerFuzzTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(),
            "antistealer-fuzz-" + Guid.NewGuid().ToString("N").Substring(0, 8));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    private string WriteSample(string name, byte[] bytes)
    {
        var path = Path.Combine(_tempDir, name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static void AssertValid(AnalysisResult r)
    {
        Assert.NotNull(r);
        Assert.InRange(r.RiskScore, 0, 100);
        Assert.Contains(r.RiskLevel, new[] { "LOW", "MEDIUM", "HIGH" });
    }

    // ----------------------------------------------------------------
    // 6.6.A — random byte streams of various sizes
    // ----------------------------------------------------------------
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(1024)]
    [InlineData(64 * 1024)]
    [InlineData(512 * 1024)]
    public void Fuzz_RandomBytes_DoesNotThrowAndTerminatesQuickly(int size)
    {
        var rng = new Random(unchecked((int)0xDEADBEEF) ^ size);
        var bytes = new byte[size];
        rng.NextBytes(bytes);
        var path = WriteSample($"rand-{size}.bin", bytes);

        var sw = Stopwatch.StartNew();
        var r = Analyzer.Analyze(path, path);
        sw.Stop();

        AssertValid(r);
        Assert.True(sw.Elapsed.TotalSeconds < 30,
            $"Analyzer took {sw.Elapsed.TotalSeconds:0.0}s on {size}B random — possible perf regression.");
    }

    // ----------------------------------------------------------------
    // 6.6.B — malformed PE: just an MZ header pointing at garbage
    // ----------------------------------------------------------------
    [Fact]
    public void Fuzz_MalformedPe_MzHeaderOnly_DoesNotThrow()
    {
        // 'MZ' + 62 bytes of padding so e_lfanew points at offset 0x80 which
        // we'll fill with garbage. Analyzer should treat it as "not PE / bad PE"
        // without crashing on the PE parser path.
        var buf = new byte[256];
        buf[0] = (byte)'M'; buf[1] = (byte)'Z';
        // e_lfanew at 0x3C = 0x80
        buf[0x3C] = 0x80; buf[0x3D] = 0; buf[0x3E] = 0; buf[0x3F] = 0;
        // Fill PE header offset with junk
        for (int i = 0x80; i < buf.Length; i++) buf[i] = (byte)(i ^ 0xAA);

        var path = WriteSample("malformed.exe", buf);
        var r = Analyzer.Analyze(path, path);
        AssertValid(r);
    }

    [Fact]
    public void Fuzz_MalformedPe_ELfanewOutOfBounds_DoesNotThrow()
    {
        // e_lfanew points way past EOF — historical OOB-read bug magnet.
        var buf = new byte[128];
        buf[0] = (byte)'M'; buf[1] = (byte)'Z';
        buf[0x3C] = 0xFF; buf[0x3D] = 0xFF; buf[0x3E] = 0xFF; buf[0x3F] = 0x7F;

        var path = WriteSample("oob-lfanew.exe", buf);
        var r = Analyzer.Analyze(path, path);
        AssertValid(r);
    }

    [Fact]
    public void Fuzz_MalformedPe_NoOptionalHeader_DoesNotThrow()
    {
        // 'MZ' + valid e_lfanew → 'PE\0\0' + COFF header but optional-header
        // size is zero. Many PE parsers will deref into garbage; ours must not.
        var buf = new byte[512];
        buf[0] = (byte)'M'; buf[1] = (byte)'Z';
        buf[0x3C] = 0x80; buf[0x3D] = 0; buf[0x3E] = 0; buf[0x3F] = 0;
        buf[0x80] = (byte)'P'; buf[0x81] = (byte)'E'; buf[0x82] = 0; buf[0x83] = 0;
        // COFF: machine=0x8664, num-sections=0, ... optional-header-size=0
        buf[0x84] = 0x64; buf[0x85] = 0x86;
        // numberOfSections=0, timeDateStamp=0, ptrToSymbolTable=0, numSymbols=0
        // sizeOfOptionalHeader = 0 at offset 0x94
        buf[0x94] = 0; buf[0x95] = 0;

        var path = WriteSample("no-opt-header.exe", buf);
        var r = Analyzer.Analyze(path, path);
        AssertValid(r);
    }

    // ----------------------------------------------------------------
    // 6.6.C — truncated archives & known magic numbers
    // ----------------------------------------------------------------
    [Fact]
    public void Fuzz_TruncatedZip_DoesNotThrow()
    {
        // "PK\x03\x04" then garbage — truncated ZIP local file header
        var buf = new byte[64];
        buf[0] = (byte)'P'; buf[1] = (byte)'K'; buf[2] = 0x03; buf[3] = 0x04;
        new Random(1).NextBytes(buf.AsSpan(4));

        var path = WriteSample("truncated.zip", buf);
        var r = Analyzer.Analyze(path, path);
        AssertValid(r);
    }

    [Fact]
    public void Fuzz_TruncatedElf_DoesNotThrow()
    {
        // \x7FELF then garbage
        var buf = new byte[32];
        buf[0] = 0x7F; buf[1] = (byte)'E'; buf[2] = (byte)'L'; buf[3] = (byte)'F';
        new Random(2).NextBytes(buf.AsSpan(4));

        var path = WriteSample("truncated.elf", buf);
        var r = Analyzer.Analyze(path, path);
        AssertValid(r);
    }

    [Fact]
    public void Fuzz_TruncatedPdf_DoesNotThrow()
    {
        // "%PDF-1." then truncated body
        var buf = new byte[32];
        var hdr = System.Text.Encoding.ASCII.GetBytes("%PDF-1.4\n");
        Buffer.BlockCopy(hdr, 0, buf, 0, hdr.Length);
        for (int i = hdr.Length; i < buf.Length; i++) buf[i] = (byte)(i & 0xFF);

        var path = WriteSample("truncated.pdf", buf);
        var r = Analyzer.Analyze(path, path);
        AssertValid(r);
    }

    // ----------------------------------------------------------------
    // 6.6.D — pathological text payloads
    // ----------------------------------------------------------------
    [Fact]
    public void Fuzz_HugeAsciiBlob_DoesNotHang()
    {
        // 4 MiB of printable ASCII — exercises ExtractAsciiStrings + regex sweeps.
        var rng = new Random(3);
        var buf = new byte[4 * 1024 * 1024];
        for (int i = 0; i < buf.Length; i++) buf[i] = (byte)(0x20 + rng.Next(0x5E));

        var path = WriteSample("ascii-blob.bin", buf);
        var sw = Stopwatch.StartNew();
        var r = Analyzer.Analyze(path, path);
        sw.Stop();
        AssertValid(r);
        Assert.True(sw.Elapsed.TotalSeconds < 60,
            $"Analyzer took {sw.Elapsed.TotalSeconds:0.0}s on 4MB ASCII — regex ReDoS?");
    }

    [Fact]
    public void Fuzz_AllNullBytes_DoesNotThrow()
    {
        var buf = new byte[64 * 1024]; // zeros
        var path = WriteSample("zeros.bin", buf);
        var r = Analyzer.Analyze(path, path);
        AssertValid(r);
    }

    [Fact]
    public void Fuzz_AllFfBytes_DoesNotThrow()
    {
        var buf = new byte[64 * 1024];
        Array.Fill(buf, (byte)0xFF);
        var path = WriteSample("ffs.bin", buf);
        var r = Analyzer.Analyze(path, path);
        AssertValid(r);
    }

    // ----------------------------------------------------------------
    // 6.6.E — file-not-found / unreadable
    // ----------------------------------------------------------------
    [Fact]
    public void Fuzz_NonExistentPath_ReturnsErrorResult()
    {
        // Per Analyzer.Error contract, analyzing a missing file returns a
        // result with RiskScore == 0 (or however Error() chose to score it),
        // but must NOT throw.
        var missing = Path.Combine(_tempDir, "does-not-exist-" + Guid.NewGuid().ToString("N") + ".bin");
        var r = Analyzer.Analyze(missing, missing);
        Assert.NotNull(r);
        // Best-effort: error-path either uses RiskScore=0 or surfaces a string
        // hit. Either way it must be a valid result object.
        Assert.InRange(r.RiskScore, 0, 100);
    }
}
