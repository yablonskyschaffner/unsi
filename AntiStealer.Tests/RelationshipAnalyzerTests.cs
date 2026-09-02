using System.Linq;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests;

/// <summary>
/// P5 + P6 + P7 — parent-child relationship graph + EXE/DLL pair
/// detection + ASI family classification.
/// </summary>
public class RelationshipAnalyzerTests
{
    private static AnalysisResult Parent(string path = "/synthetic/bundle.zip")
    {
        return new AnalysisResult(path)
        {
            FormatFamily = "ZIP",
            FileType     = "ZIP archive",
        };
    }
    private static AnalysisResult LuaChild(string path, bool downloadAndLoadChain = false)
    {
        return new AnalysisResult(path)
        {
            FormatFamily             = "Script-LUA",
            FileType                 = "Script-LUA script",
            LuaDownloadAndLoadChain  = downloadAndLoadChain,
        };
    }
    private static AnalysisResult AsiChild(string path, bool protect = false)
    {
        var r = new AnalysisResult(path)
        {
            FormatFamily = "PE-DLL-ASI",
            FileType     = "PE DLL (ASI)",
            IsDll        = true,
        };
        if (protect)
        {
            r.SectionEntropy[".themida"] = 7.95;
            r.SectionNames.Add(".themida");
            r.ExecutableWritableSections.Add(".themida");
            r.ImportedApis.Add("LoadLibraryA");
            r.ImportedApis.Add("GetProcAddress");
            r.ImportedApis.Add("VirtualAlloc");
            ProtectionAnalyzer.Compute(r);
        }
        return r;
    }
    private static AnalysisResult ExeChild(string path, bool signed)
    {
        return new AnalysisResult(path)
        {
            FormatFamily = "PE-EXE",
            FileType     = "PE EXE",
            IsExe        = true,
            IsSigned     = signed,
        };
    }
    private static AnalysisResult DllChild(string path)
    {
        return new AnalysisResult(path)
        {
            FormatFamily = "PE-DLL",
            FileType     = "PE DLL",
            IsDll        = true,
        };
    }

    [Fact]
    public void P5_LuaPlusNative_InSameArchive_ProducesEdge()
    {
        var parent = Parent();
        parent.Children.Add(LuaChild("/synthetic/bundle.zip/loader.lua"));
        parent.Children.Add(AsiChild("/synthetic/bundle.zip/payload.asi"));
        RelationshipAnalyzer.Build(parent);
        Assert.Contains(parent.RelationshipEvidence,
            e => e.Kind == "archive-contains-loader-and-payload");
    }

    [Fact]
    public void P5_LuaWithL8Chain_LiftsMarkerOntoParent()
    {
        var parent = Parent();
        parent.Children.Add(LuaChild("/x/loader.lua", downloadAndLoadChain: true));
        parent.Children.Add(AsiChild("/x/payload.asi"));
        RelationshipAnalyzer.Build(parent);
        Assert.True(parent.LuaDownloadAndLoadChain,
                    "L8 chain marker should be lifted onto parent");
        Assert.Contains(parent.RelationshipEvidence,
            e => e.Kind == "lua-downloads-dll");
    }

    [Fact]
    public void P5_ProtectedNativeChild_IsExplicitEdge()
    {
        var parent = Parent();
        parent.Children.Add(AsiChild("/x/payload.asi", protect: true));
        RelationshipAnalyzer.Build(parent);
        Assert.Contains(parent.RelationshipEvidence,
            e => e.Kind == "protected-native-child");
    }

    [Fact]
    public void P6_SignedExe_PlusSystemSideloadDll_ProducesEdge()
    {
        var parent = Parent();
        parent.Children.Add(ExeChild("/x/app.exe", signed: true));
        parent.Children.Add(DllChild("/x/version.dll"));
        RelationshipAnalyzer.Build(parent);
        Assert.Contains(parent.RelationshipEvidence,
            e => e.Kind == "exe-and-sideload-target-dll");
    }

    [Fact]
    public void P6_SignedExeImportsLocalDll_ProducesEdge()
    {
        var parent = Parent();
        var exe = ExeChild("/x/Host.exe", signed: true);
        exe.ImportedApis.Add("Custom.dll");
        parent.Children.Add(exe);
        parent.Children.Add(DllChild("/x/Custom.dll"));
        RelationshipAnalyzer.Build(parent);
        Assert.Contains(parent.RelationshipEvidence,
            e => e.Kind == "signed-exe-loads-nearby-dll");
    }

    [Fact]
    public void P6_UnsignedExe_DoesNotProducePair()
    {
        var parent = Parent();
        parent.Children.Add(ExeChild("/x/app.exe", signed: false));
        parent.Children.Add(DllChild("/x/version.dll"));
        RelationshipAnalyzer.Build(parent);
        Assert.DoesNotContain(parent.RelationshipEvidence,
            e => e.Kind == "exe-and-sideload-target-dll");
    }

    [Fact]
    public void P5_Idempotent_RebuildsCleanly()
    {
        var parent = Parent();
        parent.Children.Add(LuaChild("/x/loader.lua", true));
        parent.Children.Add(AsiChild("/x/payload.asi"));
        RelationshipAnalyzer.Build(parent);
        int n1 = parent.RelationshipEvidence.Count;
        RelationshipAnalyzer.Build(parent);
        int n2 = parent.RelationshipEvidence.Count;
        Assert.Equal(n1, n2);
    }

    [Fact]
    public void P7_AsiFamilyIsPeDllAsi_GameModFloorFires()
    {
        var r = new AnalysisResult("/x/payload.asi")
        {
            FormatFamily = "PE-DLL-ASI",
            FileType     = "PE DLL (ASI)",
            IsDll        = true,
        };
        r.SectionEntropy[".vmp0"] = 7.95;
        r.SectionNames.Add(".vmp0");
        r.ExecutableWritableSections.Add(".vmp0");
        r.ImportedApis.Add("LoadLibraryA");
        r.ImportedApis.Add("GetProcAddress");
        r.ImportedApis.Add("VirtualAlloc");
        int s = Analyzer.ScorePublic(r);
        Assert.True(s >= 60,
            $"expected ASI family + protected to floor at 60, got {s}");
        Assert.Contains("ProtectedDllInGameModContext", r.AppliedFloors);
    }

    [Fact]
    public void P5_NoChildren_LeavesEvidenceEmpty()
    {
        var parent = Parent();
        RelationshipAnalyzer.Build(parent);
        Assert.Empty(parent.RelationshipEvidence);
    }
}
