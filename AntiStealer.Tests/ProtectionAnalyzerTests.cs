using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests;

/// <summary>
/// P1...P4 + P11 + P12 — protector / packer suspicion engine
/// regression tests.
/// </summary>
public class ProtectionAnalyzerTests
{
    private static AnalysisResult NewPe(string family = "PE", bool isDll = false)
    {
        return new AnalysisResult("/synthetic/test.exe")
        {
            FormatFamily = family,
            FileType     = isDll ? "PE DLL" : "PE EXE",
            IsDll        = isDll,
        };
    }

    [Fact]
    public void P1_NonPe_LeavesProtectionEmpty()
    {
        var r = new AnalysisResult("/synthetic/x.txt")
        {
            FormatFamily = "Script-LUA",
            FileType     = "Script-LUA script",
        };
        ProtectionAnalyzer.Compute(r);
        Assert.False(r.Protection.IsProtected);
        Assert.Equal(0, r.Protection.PackedScore);
    }

    [Fact]
    public void P1_HighEntropyExecutableSection_IsReason()
    {
        var r = NewPe();
        r.SectionEntropy[".text"] = 7.85;
        ProtectionAnalyzer.Compute(r);
        Assert.True(r.Protection.HasHighEntropyCode);
        Assert.Contains(r.Protection.Reasons,
                        s => s.StartsWith("section:.text:entropy=", System.StringComparison.Ordinal));
    }

    [Fact]
    public void P1_RwxSection_IsReason()
    {
        var r = NewPe();
        r.ExecutableWritableSections.Add(".vmp0");
        ProtectionAnalyzer.Compute(r);
        Assert.True(r.Protection.HasRwxSection);
        Assert.Contains(r.Protection.Reasons,
                        s => s.StartsWith("section:rwx=", System.StringComparison.Ordinal));
    }

    [Fact]
    public void P1_FewImports_IsReason()
    {
        var r = NewPe();
        r.ImportedApis.Add("LoadLibraryA");
        r.ImportedApis.Add("GetProcAddress");
        ProtectionAnalyzer.Compute(r);
        Assert.True(r.Protection.HasFewImports);
        Assert.Contains(r.Protection.Reasons,
                        s => s.StartsWith("imports:count=", System.StringComparison.Ordinal));
    }

    [Fact]
    public void P3_DynamicApiResolution_FlaggedWhenResolversDominate()
    {
        var r = NewPe();
        r.ImportedApis.Add("LoadLibraryA");
        r.ImportedApis.Add("GetProcAddress");
        r.ImportedApis.Add("VirtualAlloc");
        r.ImportedApis.Add("VirtualProtect");
        r.ImportedApis.Add("ExitProcess");
        ProtectionAnalyzer.Compute(r);
        Assert.True(r.Protection.HasDynamicApiResolution);
        Assert.Contains(r.Protection.Reasons,
                        s => s.StartsWith("imports:resolver=", System.StringComparison.Ordinal));
    }

    [Fact]
    public void P2_ThemidaSectionName_GuessesThemida()
    {
        var r = NewPe();
        r.SectionNames.Add(".themida");
        r.SectionEntropy[".themida"] = 7.95;
        r.ImportedApis.Add("LoadLibraryA");
        r.ImportedApis.Add("GetProcAddress");
        ProtectionAnalyzer.Compute(r);
        Assert.Equal("Themida", r.Protection.ProtectorGuess);
        Assert.True(r.Protection.HasPackerSectionName);
    }

    [Fact]
    public void P2_VmprotectSectionName_GuessesVmprotect()
    {
        var r = NewPe();
        r.SectionNames.Add(".vmp0");
        r.SectionEntropy[".vmp0"] = 7.95;
        ProtectionAnalyzer.Compute(r);
        Assert.Equal("VMProtect", r.Protection.ProtectorGuess);
    }

    [Fact]
    public void P4_AntiDebugApi_RecordedInAntiAnalysisHits()
    {
        var r = NewPe();
        r.ImportedApis.Add("IsDebuggerPresent");
        r.ImportedApis.Add("CheckRemoteDebuggerPresent");
        ProtectionAnalyzer.Compute(r);
        Assert.True(r.Protection.HasAntiDebugApis);
        Assert.Contains("api:IsDebuggerPresent", r.Protection.AntiAnalysisHits);
    }

    [Fact]
    public void P4_VmString_RecordedAsAntiVm()
    {
        var r = NewPe();
        r.StringHits.Add("VirtualBox Guest Additions");
        ProtectionAnalyzer.Compute(r);
        Assert.True(r.Protection.HasAntiVmStrings);
        Assert.Contains(r.Protection.AntiAnalysisHits,
                        s => s.StartsWith("string:VirtualBox", System.StringComparison.Ordinal));
    }

    [Fact]
    public void P1_GenericProtectedGuessForUnknownPacker()
    {
        // High entropy + few imports + resolver pattern + RWX.
        var r = NewPe();
        r.SectionEntropy[".text"] = 7.95;
        r.ExecutableWritableSections.Add(".text");
        r.ImportedApis.Add("LoadLibraryA");
        r.ImportedApis.Add("GetProcAddress");
        r.ImportedApis.Add("VirtualAlloc");
        ProtectionAnalyzer.Compute(r);
        Assert.True(r.Protection.IsProtected);
        Assert.Equal("Themida-like / VM-protected", r.Protection.ProtectorGuess);
    }

    [Fact]
    public void P12_LimitedStaticVisibility_WhenProtectedAndNoBehavior()
    {
        var r = NewPe();
        r.SectionEntropy[".text"] = 7.95;
        r.ExecutableWritableSections.Add(".text");
        r.ImportedApis.Add("LoadLibraryA");
        r.ImportedApis.Add("GetProcAddress");
        r.ImportedApis.Add("VirtualAlloc");
        ProtectionAnalyzer.Compute(r);
        Assert.True(r.Protection.IsProtected);
        Assert.Equal("limited_static_visibility", r.AnalysisStatus);
        Assert.Equal("dynamic-memory-scan", r.RecommendedNextStage);
    }

    [Fact]
    public void P12_NotLimited_WhenProtectedButBehaviorObserved()
    {
        var r = NewPe();
        r.SectionEntropy[".text"] = 7.95;
        r.ExecutableWritableSections.Add(".text");
        r.ImportedApis.Add("LoadLibraryA");
        r.ImportedApis.Add("GetProcAddress");
        r.ImportedApis.Add("VirtualAlloc");
        r.AppliedFloors.Add("BrowserDbDpapiExfil");
        ProtectionAnalyzer.Compute(r);
        Assert.True(r.Protection.IsProtected);
        Assert.Equal("ok", r.AnalysisStatus);
        Assert.Null(r.RecommendedNextStage);
    }

    [Fact]
    public void P12_Idempotent_RepeatedComputeDoesNotDoubleCount()
    {
        var r = NewPe();
        r.SectionEntropy[".text"] = 7.95;
        r.ExecutableWritableSections.Add(".text");
        r.ImportedApis.Add("LoadLibraryA");
        r.ImportedApis.Add("GetProcAddress");
        r.ImportedApis.Add("VirtualAlloc");
        ProtectionAnalyzer.Compute(r);
        int s1 = r.Protection.PackedScore;
        ProtectionAnalyzer.Compute(r);
        int s2 = r.Protection.PackedScore;
        Assert.Equal(s1, s2);
    }

    [Fact]
    public void P11_LuaLoadsProtectedPayload_FloorAt92()
    {
        var r = NewPe();
        // Lua loader chain marker simulating L8 hit on a parent
        // Lua file that has now been resolved into this PE.
        r.LuaDownloadAndLoadChain = true;
        // Make the file protected.
        r.SectionEntropy[".themida"] = 7.95;
        r.SectionNames.Add(".themida");
        r.ImportedApis.Add("LoadLibraryA");
        r.ImportedApis.Add("GetProcAddress");
        r.ImportedApis.Add("VirtualAlloc");
        r.ExecutableWritableSections.Add(".themida");
        int s = Analyzer.ScorePublic(r);
        Assert.True(s >= 92,
                    $"expected protected-Lua-load to floor at 92, got {s}");
        Assert.Contains("LuaLoadsProtectedPayload", r.AppliedFloors);
    }

    [Fact]
    public void P11_ProtectedDllInGameModContext_FloorAt60()
    {
        var r = NewPe(family: "PE-DLL-ASI", isDll: true);
        r.SectionEntropy[".vmp0"] = 7.95;
        r.SectionNames.Add(".vmp0");
        r.ExecutableWritableSections.Add(".vmp0");
        r.ImportedApis.Add("LoadLibraryA");
        r.ImportedApis.Add("GetProcAddress");
        r.ImportedApis.Add("VirtualAlloc");
        int s = Analyzer.ScorePublic(r);
        Assert.True(s >= 60,
                    $"expected protected DLL in game mod context to floor at 60, got {s}");
        Assert.Contains("ProtectedDllInGameModContext", r.AppliedFloors);
    }

    [Fact]
    public void P11_ProtectedPlusCredentialExfil_FloorAt98()
    {
        var r = NewPe();
        r.SectionEntropy[".text"] = 7.95;
        r.ExecutableWritableSections.Add(".text");
        r.ImportedApis.Add("LoadLibraryA");
        r.ImportedApis.Add("GetProcAddress");
        r.ImportedApis.Add("VirtualAlloc");
        r.AppliedFloors.Add("BrowserDbDpapiExfil");
        int s = Analyzer.ScorePublic(r);
        Assert.True(s >= 98,
                    $"expected packed credential stealer to floor at 98, got {s}");
        Assert.Contains("ProtectedCredentialExfil", r.AppliedFloors);
    }

    [Fact]
    public void P1_NotProtected_WhenOnlySingleWeakIndicator()
    {
        var r = NewPe();
        // Only large overlay — by itself a 12-pt signal, well
        // below the 60-pt threshold.
        r.OverlaySize = 4 * 1024 * 1024;
        ProtectionAnalyzer.Compute(r);
        Assert.False(r.Protection.IsProtected);
        Assert.NotEqual("limited_static_visibility", r.AnalysisStatus);
    }
}
