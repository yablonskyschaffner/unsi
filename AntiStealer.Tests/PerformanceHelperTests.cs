// Section 5 — coverage for the new performance helpers introduced
// alongside the Aho-Corasick / ArrayPool / lazy-rule changes:
//   * Needles (5.1)            — AC over the static needle lists.
//   * AnalyzerLimits.AdaptiveSearchTextCap (5.6) — buffer sizing.
//   * BigFileReader (5.5)      — heap fallback + MMF round-trip.
// Behavioural correctness only; the throughput numbers live in
// AntiStealer.Benchmarks.
using System;
using System.IO;
using System.Linq;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests;

public class PerformanceHelperTests
{
    [Fact]
    public void Needles_SuspiciousString_MatchesKnownToken()
    {
        var hits = Needles.SuspiciousStringAc.Value
            .FindUniquePatterns("user opened Login Data and dumped Local State");
        Assert.Contains("login data",  hits);
        Assert.Contains("local state", hits);
    }

    [Fact]
    public void Needles_SuspiciousString_IgnoresUnrelatedText()
    {
        var hits = Needles.SuspiciousStringAc.Value
            .FindUniquePatterns("just a benign sentence with no needles");
        Assert.Empty(hits);
    }

    [Fact]
    public void Needles_MatchSuspiciousApis_ReturnsCanonicalCasing()
    {
        var imports = new[] { "cryptunprotectdata", "BCryptDecrypt", "kernel32!OpenProcess" };
        var matched = Needles.MatchSuspiciousApis(imports);
        Assert.Contains("CryptUnprotectData", matched);
        Assert.Contains("BCryptDecrypt",      matched);
        Assert.Contains("OpenProcess",        matched);
    }

    [Fact]
    public void Needles_MatchSuspiciousApis_EmptyInputYieldsEmpty()
    {
        Assert.Empty(Needles.MatchSuspiciousApis(Array.Empty<string>()));
        Assert.Empty(Needles.MatchSuspiciousApis(new[] { "", null! }!));
    }

    [Theory]
    [InlineData(0L,           64 * 1024)]
    [InlineData(1024L,        64 * 1024)]
    [InlineData(63L * 1024,   64 * 1024)]
    [InlineData(64L * 1024,   256 * 1024)]
    [InlineData(900L * 1024,  256 * 1024)]
    [InlineData(2L * 1024 * 1024, 512 * 1024)]
    [InlineData(7L * 1024 * 1024, 512 * 1024)]
    [InlineData(20L * 1024 * 1024, AnalyzerLimits.MaxSearchTextChars)]
    public void AdaptiveSearchTextCap_ScalesByFileSize(long fileSize, int expected)
    {
        Assert.Equal(expected, AnalyzerLimits.AdaptiveSearchTextCap(fileSize));
    }

    [Fact]
    public void BigFileReader_SmallFile_UsesHeapPath()
    {
        var path = Path.Combine(Path.GetTempPath(), "bfr-small-" + Guid.NewGuid().ToString("N") + ".bin");
        var data = Enumerable.Range(0, 4096).Select(i => (byte)(i & 0xff)).ToArray();
        File.WriteAllBytes(path, data);
        try
        {
            using var r = BigFileReader.Open(path);
            Assert.Equal(data.Length, r.Length);

            var dst = new byte[64];
            int n = r.ReadAt(0, dst, 64);
            Assert.Equal(64, n);
            for (int i = 0; i < 64; i++) Assert.Equal(data[i], dst[i]);

            int m = r.ReadAt(1024, dst, 64);
            Assert.Equal(64, m);
            for (int i = 0; i < 64; i++) Assert.Equal(data[1024 + i], dst[i]);
        }
        finally { try { File.Delete(path); } catch { /* best-effort */ } }
    }

    [Fact]
    public void BigFileReader_AboveThreshold_UsesMmfPathAndRoundTrips()
    {
        // 256 KiB sample with a 128 KiB threshold so we exercise the MMF
        // branch even on machines where allocating a 50 MiB temp file
        // would be wasteful in CI.
        var path = Path.Combine(Path.GetTempPath(), "bfr-big-" + Guid.NewGuid().ToString("N") + ".bin");
        var rng  = new Random(42);
        var data = new byte[256 * 1024];
        rng.NextBytes(data);
        File.WriteAllBytes(path, data);
        try
        {
            using var r = BigFileReader.Open(path, thresholdBytes: 128 * 1024);
            Assert.Equal(data.Length, r.Length);

            var dst = new byte[8 * 1024];
            int n = r.ReadAt(100_000, dst, dst.Length);
            Assert.Equal(dst.Length, n);
            for (int i = 0; i < dst.Length; i++)
                Assert.Equal(data[100_000 + i], dst[i]);
        }
        finally { try { File.Delete(path); } catch { /* best-effort */ } }
    }

    [Fact]
    public void BigFileReader_ReadPastEof_Throws()
    {
        var path = Path.Combine(Path.GetTempPath(), "bfr-eof-" + Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllBytes(path, new byte[16]);
        try
        {
            using var r = BigFileReader.Open(path);
            Assert.Throws<ArgumentOutOfRangeException>(() => r.ReadAt(0, new byte[32], 32));
        }
        finally { try { File.Delete(path); } catch { /* best-effort */ } }
    }
}
