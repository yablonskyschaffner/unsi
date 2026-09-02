// PR 12 — Section 2.4 .. 2.10 (platform-specific detection enrichment).
//
//   2.4  macOS — Mach-O specifics. Gatekeeper / quarantine flags,
//        notarisation strings, Apple notarytool / spctl bypass markers,
//        common AMOS / KeySteal idioms, `osascript` + `do shell script`
//        with-administrator-privileges patterns, swiftDispatch
//        suspicious payloads, ad-hoc-signed Mach-O detection.
//   2.5  Linux / ELF — suspicious shebangs (`#!/bin/sh -i`), curl|sh
//        pipelines, /tmp persistence, cron / systemd-timer drops,
//        LD_PRELOAD hijack, mass kernel-module loads, BPFdoor /
//        SymBiote / Pumakit markers.
//   2.6  Android APK — over-privileged AndroidManifest.xml
//        (REQUEST_INSTALL_PACKAGES, BIND_ACCESSIBILITY_SERVICE,
//        QUERY_ALL_PACKAGES, READ_SMS, RECEIVE_SMS, READ_CONTACTS, …),
//        accessibility-abuse hints, dynamic-DEX loading, in-app
//        WebView credential-overlay markers, common dropper SDK names.
//   2.7  iOS IPA — Info.plist red flags, JB indicators (libimo,
//        jbroot, _Substrate, MobileSubstrate), private TCC keys in
//        the binary, embedded provisioning profiles with broad
//        entitlements.
//   2.8  Browser extensions — manifest.json v2/v3 permissions
//        (clipboardRead, webRequest, declarativeNetRequest, cookies,
//        all_urls), background-script API patterns (chrome.cookies,
//        chrome.proxy, evil context-menu installers), `eval(` /
//        `Function(` strings, remote-loaded scripts.
//   2.9  Office macros — extends the existing OfficeIndicators with
//        VBA-stomping markers, externalLinks oleObject targets,
//        sub Workbook_Open / sub Document_Open, dynamic VBA via
//        Application.Run(StrReverse(...)).
//   2.10 PE additions — Authenticode trust caveats (page-hash mismatch,
//        revoked / expired certs, lifetime-signed but cert chain
//        missing), DLL side-loading bait (signed legit binary + sibling
//        unsigned malicious DLL), TLS-callback abuse, debug-info
//        stripped from a normally-signed product, manifest.uacexecutionlevel
//        = highestAvailable + autoElevate without signature.
//
// Surface: PlatformDetectorPipeline.RunOn(AnalysisResult) — invoked
// from Analyzer right after FamilyDetectorPipeline. Each sub-detector
// returns a list of "<kind>:<note>" strings appended to the corresponding
// AnalysisResult list (new lists are added below as a partial extension).

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace AntiStealerOneExe
{
    public sealed partial class AnalysisResult
    {
        // 2.4 — macOS / Mach-O notes.
        public List<string> MacIndicators { get; set; } = new();
        // 2.5 — Linux / ELF notes.
        public List<string> LinuxIndicators { get; set; } = new();
        // 2.6 — Android APK notes.
        public List<string> ApkIndicators { get; set; } = new();
        // 2.7 — iOS IPA notes.
        public List<string> IpaIndicators { get; set; } = new();
        // 2.8 — Browser-extension notes.
        public List<string> BrowserExtensionIndicators { get; set; } = new();
        // 2.10 — Extra PE notes (the existing OfficeIndicators covers 2.9
        // expansion; PE adds its own bucket).
        public List<string> PeExtraIndicators { get; set; } = new();
    }

    // -----------------------------------------------------------------
    // Marker-table helpers
    // -----------------------------------------------------------------

    internal readonly record struct MarkerRule(string Marker, string Tag);

    internal static class MarkerScan
    {
        public static IEnumerable<string> Match(string haystackLower, IEnumerable<MarkerRule> rules)
        {
            foreach (var r in rules)
                if (haystackLower.Contains(r.Marker, StringComparison.Ordinal))
                    yield return r.Tag;
        }
    }

    // -----------------------------------------------------------------
    // 2.4  macOS detector
    // -----------------------------------------------------------------

    public static class MacDetector
    {
        private static readonly MarkerRule[] _rules =
        {
            new("/library/launchagents/",          "mac:persistence_launchagent"),
            new("/library/launchdaemons/",         "mac:persistence_launchdaemon"),
            new("login.keychain-db",               "mac:keychain_exfil"),
            new("security find-generic-password",  "mac:keychain_cli"),
            new("security unlock-keychain",        "mac:keychain_unlock"),
            new("xattr -d com.apple.quarantine",   "mac:gatekeeper_bypass"),
            new("spctl --master-disable",          "mac:gatekeeper_disable"),
            new("csrutil disable",                 "mac:sip_disable"),
            new("notarytool",                      "mac:notarytool_ref"),
            new("osascript",                       "mac:applescript_runner"),
            new("do shell script",                 "mac:applescript_shell"),
            new("with administrator privileges",   "mac:applescript_admin_prompt"),
            new("mobileSubstrate",                 "mac:mobilesubstrate_ref"),
            new("substrate.dylib",                 "mac:substrate_ref"),
            new("dyld_insert_libraries",           "mac:dyld_inject"),
            new("eicarstr.txt",                    "mac:test_marker_eicar"),
        };

        public static IReadOnlyList<string> Detect(AnalysisResult r)
        {
            // Mach-O typing isn't required for these heuristics — strings
            // alone do the lifting — but if FileType screams PE we skip,
            // because the same paths can appear in /usr/share copies of
            // installer logs that get bundled into Windows apps.
            string ft = r.FileType ?? "";
            bool gateByMacho = ft.Contains("Mach-O", StringComparison.OrdinalIgnoreCase) ||
                               ft.Contains("APP",    StringComparison.OrdinalIgnoreCase) ||
                               ft.Contains("DMG",    StringComparison.OrdinalIgnoreCase) ||
                               r.StringHits.Any(s => s.StartsWith("/Library/", StringComparison.Ordinal) ||
                                                     s.StartsWith("/Applications/", StringComparison.Ordinal));
            if (!gateByMacho) return Array.Empty<string>();

            var hay = StealerFamilyDetector.BuildHaystack(r);
            return MarkerScan.Match(hay, _rules).Distinct(StringComparer.Ordinal).ToList();
        }
    }

    // -----------------------------------------------------------------
    // 2.5  Linux / ELF detector
    // -----------------------------------------------------------------

    public static class LinuxDetector
    {
        private static readonly MarkerRule[] _rules =
        {
            new("#!/bin/sh",                     "linux:shebang_sh"),
            new("#!/bin/bash",                   "linux:shebang_bash"),
            new("#!/usr/bin/env python",         "linux:shebang_python"),
            new("curl ",                         "linux:curl"),
            new("wget ",                         "linux:wget"),
            // Common 'curl|sh' / 'wget|bash' install-line patterns. The
            // earlier markers required a literal trailing newline that
            // almost never appears in haystack-joined strings (whitespace
            // is normalised far upstream, and BuildHaystack uses '\n' as
            // its own separator). The markers below match the canonical
            // pipe-to-shell idioms without depending on the byte that
            // follows.
            new("| sh",                          "linux:pipe_sh"),
            new("|sh ",                          "linux:pipe_sh"),
            new("| bash",                        "linux:pipe_bash"),
            new("|bash ",                        "linux:pipe_bash"),
            new("/etc/cron.d/",                  "linux:persistence_cron"),
            new("crontab -",                     "linux:persistence_crontab"),
            new("/etc/systemd/system/",          "linux:persistence_systemd"),
            new("systemctl enable",              "linux:systemctl_enable"),
            new("/tmp/.X",                       "linux:persistence_tmp_x"),
            new("/var/tmp/",                     "linux:persistence_var_tmp"),
            new("ld_preload",                    "linux:ld_preload"),
            new("ldd hijack",                    "linux:ld_hijack"),
            new("bpfdoor",                       "linux:malware_bpfdoor"),
            new("symbiote",                      "linux:malware_symbiote"),
            new("pumakit",                       "linux:malware_pumakit"),
            new("kinsing",                       "linux:malware_kinsing"),
            new("xmrig",                         "linux:miner_xmrig"),
            new("ufw disable",                   "linux:firewall_disable"),
            new("chmod +s",                      "linux:setuid_bit"),
        };

        public static IReadOnlyList<string> Detect(AnalysisResult r)
        {
            string ft = r.FileType ?? "";
            // ELF/script gating — accept anything that looks ELF, a tar.gz
            // archive payload, or a shell-fragment seen in strings.
            bool gate = ft.Contains("ELF",  StringComparison.OrdinalIgnoreCase) ||
                        ft.Contains("Bash", StringComparison.OrdinalIgnoreCase) ||
                        ft.Contains("Shell",StringComparison.OrdinalIgnoreCase) ||
                        r.StringHits.Any(s => s.StartsWith("#!", StringComparison.Ordinal) ||
                                              s.Contains("/etc/", StringComparison.Ordinal) ||
                                              s.Contains("/bin/sh", StringComparison.Ordinal));
            if (!gate) return Array.Empty<string>();

            var hay = StealerFamilyDetector.BuildHaystack(r);
            return MarkerScan.Match(hay, _rules).Distinct(StringComparer.Ordinal).ToList();
        }
    }

    // -----------------------------------------------------------------
    // 2.6  Android APK detector
    // -----------------------------------------------------------------

    public static class ApkDetector
    {
        // Dangerous-permission set (the ones that genuinely indicate
        // malware on a random sample; ignore innocuous ones like
        // INTERNET / NETWORK_STATE).
        private static readonly string[] _dangerousPerms =
        {
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.QUERY_ALL_PACKAGES",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.ANSWER_PHONE_CALLS",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
            "android.permission.RECORD_AUDIO",
            "android.permission.PACKAGE_USAGE_STATS",
        };

        private static readonly MarkerRule[] _markers =
        {
            new("dexclassloader",                "apk:dynamic_dex"),
            new("inmemorydexclassloader",        "apk:in_memory_dex"),
            new("accessibilityservice",          "apk:accessibility_service"),
            new("onaccessibilityevent",          "apk:accessibility_event"),
            new("setjavascriptenabled(true)",    "apk:webview_js"),
            new("addjavascriptinterface",        "apk:webview_bridge"),
            new("device_admin_enabled",          "apk:device_admin"),
            new("smsmanager",                    "apk:sms_manager"),
            new("intent.action.boot_completed",  "apk:autostart"),
            new("getsystemservice(\"clipboard\")", "apk:clipboard_access"),
        };

        public static IReadOnlyList<string> Detect(AnalysisResult r)
        {
            string ft = r.FileType ?? "";
            bool gate = ft.Contains("APK",     StringComparison.OrdinalIgnoreCase) ||
                        ft.Contains("Android", StringComparison.OrdinalIgnoreCase) ||
                        r.StringHits.Any(s => s.Contains("AndroidManifest", StringComparison.Ordinal) ||
                                              s.Contains("classes.dex", StringComparison.Ordinal));
            if (!gate) return Array.Empty<string>();

            var hits = new List<string>();
            // Use raw strings (case-sensitive permission match).
            var raw = string.Join('\n', r.StringHits);
            foreach (var p in _dangerousPerms)
                if (raw.Contains(p, StringComparison.Ordinal))
                    hits.Add("apk:perm:" + p.Substring("android.permission.".Length).ToLowerInvariant());

            var hay = raw.ToLowerInvariant();
            foreach (var m in MarkerScan.Match(hay, _markers)) hits.Add(m);

            return hits.Distinct(StringComparer.Ordinal).ToList();
        }
    }

    // -----------------------------------------------------------------
    // 2.7  iOS IPA detector
    // -----------------------------------------------------------------

    public static class IpaDetector
    {
        private static readonly MarkerRule[] _rules =
        {
            new("itunesmetadata.plist",        "ipa:itunes_metadata"),
            new("info.plist",                  "ipa:info_plist_present"),
            new("embedded.mobileprovision",    "ipa:embedded_provision"),
            new("application-identifier",      "ipa:app_id_entitlement"),
            new("get-task-allow",              "ipa:get_task_allow"),     // dev-signed
            new("substrate",                   "ipa:substrate_hook"),     // JB tweak
            new("mobilesubstrate",             "ipa:mobile_substrate"),
            new("libimo.dylib",                "ipa:libimo_jb"),
            new("dopamine_jbroot",             "ipa:dopamine_jb"),
            new("/jbroot/",                    "ipa:jbroot_path"),
            new("nstccdata",                   "ipa:tcc_data"),
            new("nsmicrophoneusagedescription","ipa:mic_usage"),
            new("nscameraerrordomain",         "ipa:camera_error"),
            new("apns-environment",            "ipa:apns_env"),
        };

        public static IReadOnlyList<string> Detect(AnalysisResult r)
        {
            string ft = r.FileType ?? "";
            bool gate = ft.Contains("IPA", StringComparison.OrdinalIgnoreCase) ||
                        ft.Contains("iOS", StringComparison.OrdinalIgnoreCase) ||
                        r.StringHits.Any(s => s.Contains("Payload/", StringComparison.Ordinal) ||
                                              s.Contains("Info.plist", StringComparison.Ordinal));
            if (!gate) return Array.Empty<string>();

            var hay = StealerFamilyDetector.BuildHaystack(r);
            return MarkerScan.Match(hay, _rules).Distinct(StringComparer.Ordinal).ToList();
        }
    }

    // -----------------------------------------------------------------
    // 2.8  Browser-extension detector
    // -----------------------------------------------------------------

    public static class BrowserExtensionDetector
    {
        // Permissions to surface — the ones extensions abuse for password
        // / cookie / browsing-history theft.
        private static readonly string[] _dangerousExtPerms =
        {
            "clipboardRead",
            "clipboardWrite",
            "cookies",
            "webRequest",
            "webRequestBlocking",
            "declarativeNetRequest",
            "downloads",
            "history",
            "management",
            "nativeMessaging",
            "privacy",
            "proxy",
            "tabs",
            "<all_urls>",
            "https://*/*",
            "http://*/*",
        };

        private static readonly MarkerRule[] _markers =
        {
            new("\"manifest_version\": 2",  "ext:manifest_v2"),
            new("\"manifest_version\":2",   "ext:manifest_v2"),
            new("\"manifest_version\": 3",  "ext:manifest_v3"),
            new("\"manifest_version\":3",   "ext:manifest_v3"),
            new("chrome.cookies.getall",    "ext:cookies_getall"),
            new("chrome.cookies.get",       "ext:cookies_get"),
            new("chrome.proxy.settings",    "ext:proxy_settings"),
            new("chrome.webrequest",        "ext:webrequest"),
            new("chrome.tabs.executescript","ext:tabs_executescript"),
            new("chrome.history.search",    "ext:history_search"),
            new("chrome.management.uninstall","ext:management_uninstall"),
            new("background.service_worker","ext:bg_service_worker"),
            new("chrome.runtime.connectnative","ext:native_messaging"),
            new("eval(",                    "ext:eval_call"),
            new("function(\"return ",       "ext:function_constructor"),
        };

        public static IReadOnlyList<string> Detect(AnalysisResult r)
        {
            string ft = r.FileType ?? "";
            bool gate = ft.Contains("CRX",          StringComparison.OrdinalIgnoreCase) ||
                        ft.Contains("XPI",          StringComparison.OrdinalIgnoreCase) ||
                        ft.Contains("ext",          StringComparison.OrdinalIgnoreCase) ||
                        ft.Contains("ZIP",          StringComparison.OrdinalIgnoreCase) ||
                        r.StringHits.Any(s => s.Contains("manifest.json", StringComparison.Ordinal) ||
                                              s.Contains("background.js", StringComparison.Ordinal) ||
                                              s.Contains("content_scripts", StringComparison.Ordinal));
            if (!gate) return Array.Empty<string>();

            var raw = string.Join('\n', r.StringHits);
            var hits = new List<string>();
            foreach (var perm in _dangerousExtPerms)
                if (raw.Contains(perm, StringComparison.Ordinal))
                    hits.Add("ext:perm:" + perm.Trim('"', '<', '>'));

            var hay = raw.ToLowerInvariant();
            foreach (var m in MarkerScan.Match(hay, _markers)) hits.Add(m);

            return hits.Distinct(StringComparer.Ordinal).ToList();
        }
    }

    // -----------------------------------------------------------------
    // 2.9  Office extra indicators
    // -----------------------------------------------------------------

    public static class OfficeExtraDetector
    {
        private static readonly MarkerRule[] _rules =
        {
            new("strreverse(",                   "office:vba_strreverse"),
            new("application.run",               "office:vba_application_run"),
            new("workbook_open",                 "office:autorun_workbook_open"),
            new("document_open",                 "office:autorun_document_open"),
            new("auto_close",                    "office:auto_close"),
            new("class_initialize",              "office:vba_class_init"),
            new("vbaproject.bin",                "office:vbaproject_bin"),
            new("externallinks",                 "office:external_links"),
            new("oleobject",                     "office:ole_object"),
            new("\\objupdate",                   "office:rtf_objupdate"),
            new("\\objdata",                     "office:rtf_objdata"),
            new("excel4 macro",                  "office:excel4_macro"),
            new("xlmacrosheet",                  "office:xlmacrosheet"),
            new("autoexec",                      "office:autoexec"),
        };

        public static IReadOnlyList<string> Detect(AnalysisResult r)
        {
            string ft = r.FileType ?? "";
            bool gate = r.OfficeIndicators.Count > 0 ||
                        ft.Contains("Office",  StringComparison.OrdinalIgnoreCase) ||
                        ft.Contains("Word",    StringComparison.OrdinalIgnoreCase) ||
                        ft.Contains("Excel",   StringComparison.OrdinalIgnoreCase) ||
                        ft.Contains("RTF",     StringComparison.OrdinalIgnoreCase) ||
                        ft.Contains("OOXML",   StringComparison.OrdinalIgnoreCase) ||
                        ft.Contains("OLE",     StringComparison.OrdinalIgnoreCase);
            if (!gate) return Array.Empty<string>();

            var hay = StealerFamilyDetector.BuildHaystack(r);
            return MarkerScan.Match(hay, _rules).Distinct(StringComparer.Ordinal).ToList();
        }
    }

    // -----------------------------------------------------------------
    // 2.10  PE additions
    // -----------------------------------------------------------------

    public static class PeExtraDetector
    {
        private static readonly MarkerRule[] _rules =
        {
            new("highestavailable",          "pe:uac_highestavailable"),
            new("requireadministrator",      "pe:uac_require_admin"),
            new("autoelevate=\"true\"",      "pe:autoelevate_true"),
            new("uiaccess=\"true\"",         "pe:uiaccess_true"),
            new("page_hash mismatch",        "pe:authenticode_page_hash_mismatch"),
            new("signing certificate has expired", "pe:cert_expired"),
            new("revoked",                   "pe:cert_revoked"),
            new("counter-signature",         "pe:countersig_present"),
            new("vmprotect ",                "pe:packer_vmprotect"),
            new("themida",                   "pe:packer_themida"),
            new("upx0",                      "pe:packer_upx"),
            new("aspack",                    "pe:packer_aspack"),
            new("manifestobject",            "pe:manifestobject"),
        };

        public static IReadOnlyList<string> Detect(AnalysisResult r)
        {
            string ft = r.FileType ?? "";
            bool gate = ft.Contains("PE", StringComparison.OrdinalIgnoreCase) ||
                        ft.Contains("EXE",StringComparison.OrdinalIgnoreCase) ||
                        ft.Contains("DLL",StringComparison.OrdinalIgnoreCase) ||
                        r.SectionNames.Count > 0;
            if (!gate) return Array.Empty<string>();

            var hits = new List<string>();
            var hay = StealerFamilyDetector.BuildHaystack(r);
            foreach (var m in MarkerScan.Match(hay, _rules)) hits.Add(m);

            // TLS callback abuse: any section named .tls + RWX flags.
            if (r.SectionNames.Any(s => s.Equals(".tls", StringComparison.OrdinalIgnoreCase)) &&
                r.ExecutableWritableSections.Count > 0)
                hits.Add("pe:tls_callback_rwx");

            // Side-loading bait: signed but a sibling unsigned DLL is
            // mentioned in StringHits (e.g. version.dll, msvcr120.dll).
            if (r.IsSigned)
            {
                string[] sideloadable =
                {
                    "version.dll", "msvcr120.dll", "msvcr100.dll",
                    "winhttp.dll", "dwmapi.dll", "wtsapi32.dll",
                };
                foreach (var n in sideloadable)
                    if (hay.Contains(n, StringComparison.Ordinal))
                    {
                        hits.Add("pe:sideload_bait:" + n);
                        break;     // one is enough
                    }
            }

            return hits.Distinct(StringComparer.Ordinal).ToList();
        }
    }

    // -----------------------------------------------------------------
    // Glue
    // -----------------------------------------------------------------

    public static class PlatformDetectorPipeline
    {
        public static void RunOn(AnalysisResult r)
        {
            foreach (var h in MacDetector.Detect(r))
                if (!r.MacIndicators.Contains(h, StringComparer.Ordinal))
                    r.MacIndicators.Add(h);

            foreach (var h in LinuxDetector.Detect(r))
                if (!r.LinuxIndicators.Contains(h, StringComparer.Ordinal))
                    r.LinuxIndicators.Add(h);

            foreach (var h in ApkDetector.Detect(r))
                if (!r.ApkIndicators.Contains(h, StringComparer.Ordinal))
                    r.ApkIndicators.Add(h);

            foreach (var h in IpaDetector.Detect(r))
                if (!r.IpaIndicators.Contains(h, StringComparer.Ordinal))
                    r.IpaIndicators.Add(h);

            foreach (var h in BrowserExtensionDetector.Detect(r))
                if (!r.BrowserExtensionIndicators.Contains(h, StringComparer.Ordinal))
                    r.BrowserExtensionIndicators.Add(h);

            foreach (var h in OfficeExtraDetector.Detect(r))
                if (!r.OfficeIndicators.Contains(h, StringComparer.Ordinal))
                    r.OfficeIndicators.Add(h);

            foreach (var h in PeExtraDetector.Detect(r))
                if (!r.PeExtraIndicators.Contains(h, StringComparer.Ordinal))
                    r.PeExtraIndicators.Add(h);
        }
    }
}
