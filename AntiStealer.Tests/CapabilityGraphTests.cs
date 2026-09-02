using System.Linq;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests;

/// <summary>
/// P8 + P9 + P10 — .NET metadata inspector, YARA source tagging,
/// and the final capability-graph verdict.
/// </summary>
public class CapabilityGraphTests
{
    private static AnalysisResult NewPe()
    {
        return new AnalysisResult("/synthetic/p10.exe")
        {
            FormatFamily = "PE",
            FileType     = "PE EXE",
            IsExe        = true,
        };
    }

    // ---------------------------------------------------------------
    // P9 — structured YARA hit details with explicit source tagging.
    // ---------------------------------------------------------------

    [Fact]
    public void P9_YaraTagger_PushesStructuredAndLegacyEntries()
    {
        var r = NewPe();
        YaraHitTagger.AddHit(r, "file", "stealers.yar", "LummaC2_Strings", "prefix");
        Assert.Contains("stealers.yar:LummaC2_Strings", r.YaraHits);
        var d = r.YaraHitDetails.Single();
        Assert.Equal("file",            d.Source);
        Assert.Equal("stealers.yar",    d.RuleFile);
        Assert.Equal("LummaC2_Strings", d.RuleName);
        Assert.Equal("prefix",          d.Region);
    }

    [Fact]
    public void P9_YaraTagger_DeduplicatesOnLegacyForm()
    {
        var r = NewPe();
        YaraHitTagger.AddHit(r, "file",   "x.yar", "Hit");
        YaraHitTagger.AddHit(r, "file",   "x.yar", "Hit");
        Assert.Single(r.YaraHits);
        Assert.Single(r.YaraHitDetails);
    }

    [Fact]
    public void P9_YaraTagger_DistinguishesFileVsChildSource()
    {
        var r = NewPe();
        YaraHitTagger.AddHit(r, "file",  "x.yar", "Hit");
        YaraHitTagger.AddHit(r, "child", "x.yar", "Hit", region: "inner.dll");
        // Same legacy form so YaraHits has one entry, but two
        // structured details (different Source).
        Assert.Single(r.YaraHits);
        Assert.Equal(2, r.YaraHitDetails.Count);
        Assert.Contains(r.YaraHitDetails, d => d.Source == "child");
    }

    // ---------------------------------------------------------------
    // P10 — capability graph + final verdict.
    // ---------------------------------------------------------------

    [Fact]
    public void P10_VerdictBands_FromRiskScore()
    {
        foreach (var (score, expected) in new[]
        {
            (0,   "clean"),
            (24,  "clean"),
            (25,  "low"),
            (49,  "low"),
            (50,  "medium"),
            (69,  "medium"),
            (70,  "high"),
            (89,  "high"),
            (90,  "critical"),
            (100, "critical"),
        })
        {
            var r = NewPe();
            r.RiskScore = score;
            CapabilityGraph.Build(r);
            Assert.Equal(expected, r.Verdict.Verdict);
        }
    }

    [Fact]
    public void P10_VerdictConfidence_FromMaliciousConfidence()
    {
        var r = NewPe();
        r.MaliciousConfidence = 73;
        CapabilityGraph.Build(r);
        Assert.Equal(73, r.Verdict.Confidence);
    }

    [Fact]
    public void P10_VerdictReason_PrefersAppliedFloor()
    {
        var r = NewPe();
        r.AppliedFloors.Add("BrowserDbDpapiExfil");
        r.AppliedFloors.Add("LuaCredentialExfilChain");
        CapabilityGraph.Build(r);
        Assert.Equal("floor:BrowserDbDpapiExfil", r.Verdict.Reason);
    }

    [Fact]
    public void P10_VerdictReason_FallsBackToCapabilities()
    {
        var r = NewPe();
        r.CapabilityScores["CryptoTheft"] = 65;
        CapabilityGraph.Build(r);
        Assert.Equal("cap:CryptoTheft", r.Verdict.Reason);
    }

    [Fact]
    public void P10_VerdictCapabilities_OnlyAboveThreshold()
    {
        var r = NewPe();
        r.CapabilityScores["CredentialTheft"]  = 88;
        r.CapabilityScores["Exfiltration"]     = 55;
        r.CapabilityScores["Network"]          = 12; // below
        r.CapabilityScores["AllowlistMatch"]   = 100; // excluded
        CapabilityGraph.Build(r);
        Assert.Equal(new[] { "CredentialTheft", "Exfiltration" },
                     r.Verdict.Capabilities);
    }

    [Fact]
    public void P10_VerdictProtectorAndStatus_Mirrored()
    {
        var r = NewPe();
        r.Protection.ProtectorGuess = "Themida";
        r.Protection.IsProtected    = true;
        r.AnalysisStatus       = "limited_static_visibility";
        r.RecommendedNextStage = "dynamic-memory-scan";
        CapabilityGraph.Build(r);
        Assert.Equal("Themida", r.Verdict.ProtectorGuess);
        Assert.Equal("limited_static_visibility", r.Verdict.AnalysisStatus);
        Assert.Equal("dynamic-memory-scan",        r.Verdict.RecommendedNextStage);
    }

    [Fact]
    public void P10_VerdictBuild_IsIdempotent()
    {
        var r = NewPe();
        r.RiskScore = 92;
        r.CapabilityScores["CredentialTheft"] = 80;
        CapabilityGraph.Build(r);
        var first = r.Verdict;
        CapabilityGraph.Build(r);
        Assert.Equal(first.Verdict, r.Verdict.Verdict);
        Assert.Equal(first.Capabilities.Count, r.Verdict.Capabilities.Count);
    }

    // ---------------------------------------------------------------
    // P8 — .NET metadata inspector (negative path: no-op for non-.NET).
    // ---------------------------------------------------------------

    [Fact]
    public void P8_NetInspector_NoOpForNonDotNetFile()
    {
        var r = NewPe();
        r.IsDotNetLikely = false;
        NetMetadataInspector.Inspect(r, "/synthetic/nonexistent.bin");
        Assert.Empty(r.DotNetUserStringHits);
        Assert.Equal(0, r.DotNetMethodCount);
    }

    [Fact]
    public void P8_NetInspector_GracefulOnMissingFile()
    {
        var r = NewPe();
        r.IsDotNetLikely = true;
        // Must not throw even though path doesn't exist.
        NetMetadataInspector.Inspect(r, "/synthetic/does/not/exist.dll");
        Assert.Empty(r.DotNetUserStringHits);
    }
}
