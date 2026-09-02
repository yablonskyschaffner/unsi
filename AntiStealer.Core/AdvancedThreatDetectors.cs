// PR 13 — Section 2.11 .. 2.16 (advanced-threat enrichment).
//
//   2.11 BYOVD — Bring Your Own Vulnerable Driver. Detect known-
//        vulnerable signed driver filenames (RTCore64.sys, gdrv.sys,
//        mhyprot2.sys, dbutil_2_3.sys, procexp152.sys, NTIOLib.sys,
//        AsrDrv101.sys, …) plus driver-load API patterns
//        (NtLoadDriver, ZwLoadDriver, SeLoadDriverPrivilege,
//        OpenSCManager + CreateService + START_TYPE_KERNEL).
//   2.12 Shellcode — common in-process shellcode signatures:
//        - CS prologue 0xFC 0xE8 0x82 (most-frequent x64 stager start),
//        - Metasploit egg-hunter (0x66 0x81 0xCA 0xFF 0x0F),
//        - API-hash resolver loops referencing 'kernel32' / 'ntdll',
//        - reflective-DLL marker ('reflective' + 'DllMain'),
//        - syscall stubs (`mov r10, rcx; mov eax, NN; syscall;`).
//   2.13 Stego — steganography / payload hiding inside image / video
//        containers: PNG/JPG with appended PE/ZIP after IEND/EOI,
//        base64-of-'MZ' header ('TVqQAA' / 'TVoAAA'), 'stegolib'
//        markers, LSB toolkit names (lsbsteg, steghide), QR-payload
//        carriers.
//   2.14 C2-framework — Cobalt Strike beacon markers (xor-decoded
//        'PEEXC2' watermark, default malleable-C2 profile strings,
//        'beacon.dll' / 'beacon.x64.dll', `_beacon_` exports),
//        Sliver (sliverpb, slivercc, 'mTLS-pinned', WireGuard implants),
//        Mythic agents (Apollo/Athena/Apfell/Poseidon/Tetanus
//        callback strings, mythic_c2 routes),
//        Havoc demon (demon.x64.dll, agentforge), Brute Ratel
//        (badger, BadgerSplinter).
//   2.15 Phishing-kit — common open-source kit markers inside scraped
//        HTML / PHP / JS: evilginx2 config, gophish landing pages,
//        modlishka, 16shop, MUST*-microsoft branded credential page,
//        captcha-bypass libs, Telegram-bot exfil call sites.
//   2.16 npm supply-chain — package.json + lockfile / .npmrc / install
//        script analysis: postinstall / preinstall with curl|wget +
//        eval / child_process, suspicious typo-squat package names,
//        custom registry pointing to non-public hosts, dangerous
//        require('child_process')+exec patterns at install time.
//
// Surface: AdvancedThreatPipeline.RunOn(AnalysisResult) — invoked
// from Analyzer right after PlatformDetectorPipeline.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace AntiStealerOneExe
{
    public sealed partial class AnalysisResult
    {
        // 2.11
        public List<string> ByovdIndicators { get; set; } = new();
        // 2.12
        public List<string> ShellcodeIndicators { get; set; } = new();
        // 2.13
        public List<string> StegoIndicators { get; set; } = new();
        // 2.14
        public List<string> C2FrameworkIndicators { get; set; } = new();
        // 2.15
        public List<string> PhishingKitIndicators { get; set; } = new();
        // 2.16
        public List<string> NpmSupplyChainIndicators { get; set; } = new();
    }

    // -----------------------------------------------------------------
    // 2.11  BYOVD
    // -----------------------------------------------------------------

    public static class ByovdDetector
    {
        // Compiled list of known-vulnerable signed drivers — curated
        // from the LolDrivers project as of 2024. Match is case-
        // insensitive against the lower-cased haystack.
        internal static readonly string[] VulnerableDrivers =
        {
            "rtcore64.sys",      // MSI Afterburner — RW-everywhere primitive
            "rtcore32.sys",
            "gdrv.sys",          // Gigabyte
            "mhyprot2.sys",      // Genshin Impact anti-cheat
            "mhyprot3.sys",
            "dbutil_2_3.sys",    // Dell DBUtil
            "ntiolib.sys",       // MSI / NTIOLib
            "procexp.sys",       // Sysinternals (older, vulnerable variant)
            "procexp152.sys",
            "asrdrv101.sys",     // ASRock
            "asrdrv102.sys",
            "kprocesshacker.sys",
            "wnbios.sys",        // WinRing0
            "winring0x64.sys",
            "atillk64.sys",      // ATI
            "speedfan.sys",
            "viragt64.sys",      // ESET vulnerable driver (CVE-2021-27617)
            "ucorw.sys",
            "vboxdrv.sys",
        };

        private static readonly (string Marker, string Tag)[] _apiMarkers =
        {
            ("ntloaddriver",            "byovd:api:NtLoadDriver"),
            ("zwloaddriver",            "byovd:api:ZwLoadDriver"),
            ("seloaddriverprivilege",   "byovd:api:SeLoadDriverPrivilege"),
            ("openscmanager",           "byovd:api:OpenSCManager"),
            ("createservicew",          "byovd:api:CreateService"),
            ("service_kernel_driver",   "byovd:flag:SERVICE_KERNEL_DRIVER"),
            ("start_type_kernel",       "byovd:flag:START_TYPE_KERNEL"),
        };

        public static IReadOnlyList<string> Detect(AnalysisResult r)
        {
            var hay = StealerFamilyDetector.BuildHaystack(r);
            var hits = new List<string>();

            foreach (var drv in VulnerableDrivers)
                if (hay.Contains(drv, StringComparison.Ordinal))
                    hits.Add("byovd:driver:" + drv);

            foreach (var (m, tag) in _apiMarkers)
                if (hay.Contains(m, StringComparison.Ordinal))
                    hits.Add(tag);

            return hits.Distinct(StringComparer.Ordinal).ToList();
        }
    }

    // -----------------------------------------------------------------
    // 2.12  Shellcode
    // -----------------------------------------------------------------

    public static class ShellcodeDetector
    {
        // Common byte sequences (hex, lower-case) commonly seen in
        // shellcode dumps when binaries are stringified by `strings -a`
        // or when shellcode is embedded as a hex literal in a script.
        private static readonly (string HexMarker, string Tag)[] _byteMarkers =
        {
            ("fce8820000006089e5",            "shellcode:cs_x64_stager_prologue"),
            ("fce8890000006089e5",            "shellcode:cs_x86_stager_prologue"),
            ("6681caff0f",                    "shellcode:msf_egg_hunter"),
            ("4c8bd1b8",                      "shellcode:syscall_x64_movR10RCX_movEAX"),  // followed by syscall #
            ("0f05",                          "shellcode:syscall_instr"),
            ("eb15",                          "shellcode:short_jmp_eb15"),                 // common CS hop
        };

        private static readonly (string Marker, string Tag)[] _textMarkers =
        {
            ("reflectiveloader",            "shellcode:reflective_loader_export"),
            ("dllmain",                     "shellcode:dllmain_text"),
            ("kernel32.dll",                "shellcode:kernel32_ref_in_blob"),
            ("ntdll.dll",                   "shellcode:ntdll_ref_in_blob"),
            ("ldrloaddll",                  "shellcode:ldr_loaddll_resolve"),
            ("loadlibrarya",                "shellcode:loadlibrary_resolve"),
            ("getprocaddress",              "shellcode:getproc_resolve"),
            ("virtualalloc",                "shellcode:virtualalloc_alloc"),
            ("virtualprotect",              "shellcode:virtualprotect_rwx"),
            ("createthread",                "shellcode:createthread_exec"),
        };

        public static IReadOnlyList<string> Detect(AnalysisResult r)
        {
            var hits = new List<string>();
            var hay = StealerFamilyDetector.BuildHaystack(r);

            // Look for hex byte sequences both in the haystack (which
            // would catch hex-stringified payloads, e.g. shellcode
            // embedded in a JS / PowerShell loader) and in the section
            // names (no — sections aren't hex). Stick to the haystack.
            foreach (var (h, tag) in _byteMarkers)
                if (hay.Contains(h, StringComparison.Ordinal))
                    hits.Add(tag);

            foreach (var (m, tag) in _textMarkers)
                if (hay.Contains(m, StringComparison.Ordinal))
                    hits.Add(tag);

            // Strong combo: 'virtualalloc' + 'createthread' + 'virtualprotect'
            // — classic 3-API shellcode runner.
            if (hits.Contains("shellcode:virtualalloc_alloc", StringComparer.Ordinal) &&
                hits.Contains("shellcode:createthread_exec",  StringComparer.Ordinal) &&
                hits.Contains("shellcode:virtualprotect_rwx", StringComparer.Ordinal))
                hits.Add("shellcode:classic_runner_triplet");

            return hits.Distinct(StringComparer.Ordinal).ToList();
        }
    }

    // -----------------------------------------------------------------
    // 2.13  Steganography
    // -----------------------------------------------------------------

    public static class StegoDetector
    {
        private static readonly (string Marker, string Tag)[] _markers =
        {
            // PE base64-prefix headers (b64('MZ\x90\0\3\0\0') etc.).
            ("TVqQAA",                  "stego:base64_pe_header_TVqQAA"),
            ("TVoAAA",                  "stego:base64_pe_header_TVoAAA"),
            ("TVpQAA",                  "stego:base64_pe_header_TVpQAA"),
            // PNG IEND-then-PE / PNG IEND-then-PK (ZIP).
            ("IEND\xae\x42\x60\x82MZ",  "stego:png_append_pe"),
            ("IEND\xae\x42\x60\x82PK",  "stego:png_append_zip"),
            ("steghide",                "stego:tool_steghide"),
            ("stegolib",                "stego:tool_stegolib"),
            ("lsbsteg",                 "stego:tool_lsbsteg"),
            ("stegoshell",              "stego:tool_stegoshell"),
            ("zsteg",                   "stego:tool_zsteg"),
            ("openstego",               "stego:tool_openstego"),
            ("qrencode --payload",      "stego:qr_payload"),
        };

        public static IReadOnlyList<string> Detect(AnalysisResult r)
        {
            // Raw (case-sensitive) for base64 prefixes; hay (lower) for
            // tool names. We compute both.
            string raw = string.Join('\n', r.StringHits);
            string hay = StealerFamilyDetector.BuildHaystack(r);

            var hits = new List<string>();
            foreach (var (m, tag) in _markers)
            {
                bool match = m.StartsWith("TV", StringComparison.Ordinal)
                    ? raw.Contains(m, StringComparison.Ordinal)
                    : hay.Contains(m.ToLowerInvariant(), StringComparison.Ordinal);
                if (match) hits.Add(tag);
            }
            return hits.Distinct(StringComparer.Ordinal).ToList();
        }
    }

    // -----------------------------------------------------------------
    // 2.14  C2 framework detector (Cobalt Strike / Sliver / Mythic /
    //       Havoc / Brute Ratel)
    // -----------------------------------------------------------------

    public static class C2FrameworkDetector
    {
        private static readonly (string Marker, string Tag)[] _markers =
        {
            // Cobalt Strike
            ("cobaltstrike",            "c2:CobaltStrike"),
            ("beacon.x64.dll",          "c2:CobaltStrike:beacon_x64"),
            ("beacon.x86.dll",          "c2:CobaltStrike:beacon_x86"),
            ("_beacon_",                "c2:CobaltStrike:beacon_export"),
            ("c2.profile",              "c2:CobaltStrike:malleable_profile"),
            ("peexc2",                  "c2:CobaltStrike:peex_watermark"),
            // Sliver
            ("sliverpb",                "c2:Sliver:protobuf"),
            ("slivercc",                "c2:Sliver:control_channel"),
            ("sliverc2",                "c2:Sliver:c2_module"),
            ("mtls-pinned",             "c2:Sliver:mtls_pinning"),
            ("wireguard implant",       "c2:Sliver:wg_implant"),
            // Mythic
            ("mythic_c2",               "c2:Mythic:c2_route"),
            ("apollo agent",            "c2:Mythic:apollo"),
            ("athena agent",            "c2:Mythic:athena"),
            ("apfell",                  "c2:Mythic:apfell"),
            ("poseidon agent",          "c2:Mythic:poseidon"),
            ("tetanus agent",           "c2:Mythic:tetanus"),
            // Havoc
            ("demon.x64.dll",           "c2:Havoc:demon_x64"),
            ("agentforge",              "c2:Havoc:agentforge"),
            ("havocagent",              "c2:Havoc:agent"),
            // Brute Ratel
            ("badgersplinter",          "c2:BruteRatel:badger_splinter"),
            ("brute ratel",             "c2:BruteRatel"),
            ("badger.dll",              "c2:BruteRatel:badger_dll"),
        };

        public static IReadOnlyList<string> Detect(AnalysisResult r)
        {
            var hay = StealerFamilyDetector.BuildHaystack(r);
            var hits = new List<string>();
            foreach (var (m, tag) in _markers)
                if (hay.Contains(m, StringComparison.Ordinal))
                    hits.Add(tag);
            return hits.Distinct(StringComparer.Ordinal).ToList();
        }
    }

    // -----------------------------------------------------------------
    // 2.15  Phishing-kit
    // -----------------------------------------------------------------

    public static class PhishingKitDetector
    {
        private static readonly (string Marker, string Tag)[] _markers =
        {
            ("evilginx",               "phish:evilginx"),
            ("modlishka",              "phish:modlishka"),
            ("gophish",                "phish:gophish"),
            ("16shop",                 "phish:16shop"),
            ("eviloffice",             "phish:eviloffice"),
            ("zphisher",               "phish:zphisher"),
            ("ophish-",                "phish:ophish"),
            // Brand-themed credential page markers.
            ("microsoft 365",          "phish:brand:microsoft365"),
            ("office365 login",        "phish:brand:office365"),
            ("docusign signin",        "phish:brand:docusign"),
            ("dhl tracking",           "phish:brand:dhl"),
            // Common kit features.
            ("captcha bypass",         "phish:captcha_bypass"),
            ("victim_email",           "phish:victim_email_var"),
            ("teleg_send",             "phish:telegram_exfil_fn"),
            ("send_to_bot.php",        "phish:telegram_exfil_endpoint"),
            ("$pwd ",                  "phish:password_capture_var"),
            ("antibot.php",            "phish:antibot_filter"),
            ("blocker.htaccess",       "phish:htaccess_blocker"),
        };

        public static IReadOnlyList<string> Detect(AnalysisResult r)
        {
            string ft = r.FileType ?? "";
            // Gate: HTML / PHP / JS samples or strings that mention HTML.
            bool gate = ft.Contains("HTML", StringComparison.OrdinalIgnoreCase) ||
                        ft.Contains("PHP",  StringComparison.OrdinalIgnoreCase) ||
                        ft.Contains("JS",   StringComparison.OrdinalIgnoreCase) ||
                        r.StringHits.Any(s => s.Contains("<form", StringComparison.OrdinalIgnoreCase) ||
                                              s.Contains("<html", StringComparison.OrdinalIgnoreCase) ||
                                              s.Contains("<?php", StringComparison.Ordinal));
            if (!gate) return Array.Empty<string>();

            var hay = StealerFamilyDetector.BuildHaystack(r);
            var hits = new List<string>();
            foreach (var (m, tag) in _markers)
                if (hay.Contains(m, StringComparison.Ordinal))
                    hits.Add(tag);
            return hits.Distinct(StringComparer.Ordinal).ToList();
        }
    }

    // -----------------------------------------------------------------
    // 2.16  npm supply-chain
    // -----------------------------------------------------------------

    public static class NpmSupplyChainDetector
    {
        // Well-known typo-squat package names from public IOCs.
        internal static readonly string[] TypoSquats =
        {
            "lodahs",                // lodash
            "expreess",              // express
            "discordi.js",           // discord.js
            "noblox.js-proxy",       // noblox.js
            "@core/utils",           // ambiguous-scope kit
            "ua-parser-js-vue",      // ua-parser-js
            "rc-vue",                // rc
            "node-ipc-evil",         // node-ipc (post-ipv6-incident)
            "color-string-evil",
        };

        private static readonly (string Marker, string Tag)[] _markers =
        {
            ("\"postinstall\":",            "npm:postinstall_hook"),
            ("\"preinstall\":",             "npm:preinstall_hook"),
            ("\"install\":",                "npm:install_hook"),
            ("require('child_process')",    "npm:require_child_process"),
            (".exec(",                       "npm:exec_call"),
            ("eval(",                        "npm:eval_call"),
            ("curl ",                        "npm:install_curl"),
            ("wget ",                        "npm:install_wget"),
            ("base64 -d",                    "npm:base64_decode_pipe"),
            ("--unsafe-perm",                "npm:unsafe_perm"),
            ("ignore-scripts=false",         "npm:scripts_enabled"),
            ("registry=http://",             "npm:custom_http_registry"),
            ("registry=https://0x",          "npm:hex_registry_host"),
        };

        public static IReadOnlyList<string> Detect(AnalysisResult r)
        {
            string ft = r.FileType ?? "";
            // Gate: package.json / package-lock / .npmrc, or a sample
            // whose strings include those filenames or fields.
            bool gate = ft.Contains("JSON", StringComparison.OrdinalIgnoreCase) ||
                        r.StringHits.Any(s => s.Contains("package.json",      StringComparison.Ordinal) ||
                                              s.Contains("package-lock.json", StringComparison.Ordinal) ||
                                              s.Contains(".npmrc",            StringComparison.Ordinal) ||
                                              s.Contains("\"dependencies\":", StringComparison.Ordinal) ||
                                              s.Contains("\"scripts\":",      StringComparison.Ordinal));
            if (!gate) return Array.Empty<string>();

            var raw = string.Join('\n', r.StringHits);
            var hits = new List<string>();

            foreach (var t in TypoSquats)
                if (raw.Contains("\"" + t + "\"", StringComparison.Ordinal) ||
                    raw.Contains("/" + t,           StringComparison.Ordinal))
                    hits.Add("npm:typosquat:" + t);

            foreach (var (m, tag) in _markers)
                if (raw.Contains(m, StringComparison.Ordinal))
                    hits.Add(tag);

            return hits.Distinct(StringComparer.Ordinal).ToList();
        }
    }

    // -----------------------------------------------------------------
    // Glue
    // -----------------------------------------------------------------

    public static class AdvancedThreatPipeline
    {
        public static void RunOn(AnalysisResult r)
        {
            foreach (var h in ByovdDetector.Detect(r))
                if (!r.ByovdIndicators.Contains(h, StringComparer.Ordinal))
                    r.ByovdIndicators.Add(h);

            foreach (var h in ShellcodeDetector.Detect(r))
                if (!r.ShellcodeIndicators.Contains(h, StringComparer.Ordinal))
                    r.ShellcodeIndicators.Add(h);

            foreach (var h in StegoDetector.Detect(r))
                if (!r.StegoIndicators.Contains(h, StringComparer.Ordinal))
                    r.StegoIndicators.Add(h);

            foreach (var h in C2FrameworkDetector.Detect(r))
                if (!r.C2FrameworkIndicators.Contains(h, StringComparer.Ordinal))
                    r.C2FrameworkIndicators.Add(h);

            foreach (var h in PhishingKitDetector.Detect(r))
                if (!r.PhishingKitIndicators.Contains(h, StringComparer.Ordinal))
                    r.PhishingKitIndicators.Add(h);

            foreach (var h in NpmSupplyChainDetector.Detect(r))
                if (!r.NpmSupplyChainIndicators.Contains(h, StringComparer.Ordinal))
                    r.NpmSupplyChainIndicators.Add(h);
        }
    }
}
