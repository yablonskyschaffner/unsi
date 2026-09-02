using System;
using System.Collections.Generic;
using System.IO;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests;

// FF2/FF3/FF4/FF5/FF9 perf utilities — structure/correctness only (not a real benchmark).
public class PerfTests
{
    [Fact]
    public void AhoCorasick_FindsAllPatternsInText()
    {
        var ac = new AhoCorasick(new[] { "he", "she", "his", "hers" });
        var hits = ac.FindAll("ushers");
        // "she" @ 1, "he" @ 2, "hers" @ 2
        var patterns = new HashSet<string>();
        foreach (var (_, p) in hits) patterns.Add(p);
        Assert.Contains("she",  patterns);
        Assert.Contains("he",   patterns);
        Assert.Contains("hers", patterns);
    }

    [Fact]
    public void AhoCorasick_IgnoreCase_MatchesLowerAndUpper()
    {
        var ac = new AhoCorasick(new[] { "password", "token" }, ignoreCase: true);
        var set = ac.FindUniquePatterns("A PASSWORD and a TOKEN here");
        Assert.Contains("password", set);
        Assert.Contains("token",    set);
    }

    [Fact]
    public void CompiledRegex_Get_ReturnsSameInstanceForSamePattern()
    {
        var a = CompiledRegex.Get(@"\d+");
        var b = CompiledRegex.Get(@"\d+");
        Assert.Same(a, b);
        Assert.True(a.Match("abc 123 def").Success);
    }

    [Fact]
    public void FileResultCache_RoundTripsJsonBySha256()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "ast-cache-" + Guid.NewGuid().ToString("N"));
        FileResultCache.CacheRoot = tmp;
        try
        {
            var sha = new string('c', 64);
            FileResultCache.Put(sha, "{\"foo\":1}");
            Assert.True(FileResultCache.TryGet(sha, out var got));
            Assert.Equal("{\"foo\":1}", got);
        }
        finally
        {
            try { Directory.Delete(tmp, true); } catch { }
        }
    }

    [Fact]
    public void SampleHasher_Sha256AndPrefix_MatchesReference()
    {
        var path = Path.Combine(Path.GetTempPath(), "sample-" + Guid.NewGuid().ToString("N") + ".bin");
        var data = new byte[1024];
        for (int i = 0; i < data.Length; i++) data[i] = (byte)(i & 0xFF);
        File.WriteAllBytes(path, data);
        try
        {
            var (sha, prefix) = SampleHasher.Sha256AndPrefix(path, 64);
            Assert.Equal(64, prefix.Length);
            Assert.Equal(64, sha.Length);
            for (int i = 0; i < 64; i++) Assert.Equal(data[i], prefix[i]);
        }
        finally { try { File.Delete(path); } catch { } }
    }

    [Fact]
    public void PerfCounters_AccumulateTimingsAndRender()
    {
        PerfCounters.Reset();
        using (PerfCounters.Time("step-A")) { System.Threading.Thread.Sleep(1); }
        using (PerfCounters.Time("step-A")) { System.Threading.Thread.Sleep(1); }
        using (PerfCounters.Time("step-B")) { System.Threading.Thread.Sleep(1); }
        var rendered = PerfCounters.Render();
        Assert.Contains("step-A", rendered);
        Assert.Contains("step-B", rendered);
        Assert.Contains("x2", rendered); // step-A called twice
    }
}
