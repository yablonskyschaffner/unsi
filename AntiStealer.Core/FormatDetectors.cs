// CC1–CC12: format-specific detectors.
//
// Full structured parsing of MSI, APPX, Mach-O, ELF, VBA streams, PDF /JS,
// LNK ShellLinks, HTA/CHM, OneNote, and ClickOnce manifests would be ~10k LOC
// each. This module instead does deep *string-level* detection sharpened to
// the exact-byte markers and opcode sequences these formats use to carry
// malicious payloads. It runs cheaply on the already-extracted analysisText
// plus a small raw-bytes prefix, and surfaces findings in dedicated report
// sections.
//
// Each detector populates a named HitList on AnalysisResult, contributes to
// the scoring blend via FormatDetectorsBonus, and maps hits to the most
// accurate MITRE ATT&CK TTP.

namespace AntiStealerOneExe
{
    public sealed partial class AnalysisResult
    {
        // CC1  MSI (Installer) — CustomAction abuse
        public List<string> MsiCustomActionHits { get; set; } = new();
        // CC2  APPX/MSIX — dangerous capabilities
        public List<string> AppxCapabilityHits  { get; set; } = new();
        // CC3  Mach-O — load commands / encryption
        public List<string> MachOLoadCommandHits { get; set; } = new();
        // CC4  ELF — dynamic section / RPATH abuse
        public List<string> ElfDynamicHits       { get; set; } = new();
        // CC5  VBA/Office — AutoExec / dangerous calls
        public List<string> VbaMacroHits         { get; set; } = new();
        // CC6  PDF — JavaScript / OpenAction abuse
        public List<string> PdfJsActionHits      { get; set; } = new();
        // CC7  LNK — shell link abuse
        public List<string> LnkCommandHits       { get; set; } = new();
        // CC8  PowerShell deobfuscation
        public List<string> PowerShellObfHits    { get; set; } = new();
        // CC9  JS deobfuscation
        public List<string> JsObfuscationHits    { get; set; } = new();
        // CC10 HTA / CHM — execution wrappers
        public List<string> HtaChmHits           { get; set; } = new();
        // CC11 OneNote — embedded attachments
        public List<string> OneNoteEmbedHits     { get; set; } = new();
        // CC12 ClickOnce — manifest anomalies
        public List<string> ClickOnceHits        { get; set; } = new();
        // CC13 Lua — SA-MP / GTA-targeted loaders & stealers. Each hit
        // is the human-readable threat type ('Загрузчик лоадера ...',
        // 'Стиллер ...', …); the rule fires only when *every* signature
        // in its group is present in the file's binary-preserving text.
        public List<string> LuaThreatHits         { get; set; } = new();

        // B9 — modern infostealer-specific patterns. Each list is
        // populated by ModernStealerDetectors() and feeds the
        // decisive-floor recipes in Score().
        public List<string> ClickFixCaptchaHits    { get; set; } = new();
        public List<string> LummaConfigHits        { get; set; } = new();
        public List<string> BrowserExtTheftHits    { get; set; } = new();
        public List<string> MfaAppTheftHits        { get; set; } = new();
        public List<string> StealerPostBodyHits    { get; set; } = new();

        // A3 — provenance of every textual evidence. Keys are
        // EvidenceSource labels: "prefix", "tail", "overlay", ".rsrc",
        // "section:.text", "section:.data", "zip:<entry>". Values are
        // the matching needles / hit strings that came from that
        // window. Used for explainability ("the IOC was found in the
        // overlay" vs "in the prefix") and by reporting / Sigma fields.
        public Dictionary<string, List<string>> EvidenceSources { get; set; } =
            new(StringComparer.OrdinalIgnoreCase);

        // A4 — recursively analysed archive children. When the input
        // is a ZIP / JAR / APK / OOXML / 7z / .asar etc., each
        // contained entry is analysed in its own AnalysisResult; the
        // parent's RiskScore is the max of its raw score and any
        // child's score plus the container bonus.
        public List<AnalysisResult> Children { get; set; } = new();
        // Operator hint when the parent's risk was lifted by a child:
        // "child:malware.dll@bundle.zip → 87" etc.
        public List<string> ChildContainerHits { get; set; } = new();

        // A3 — convenience helper. Adds the hit to EvidenceSources[src]
        // (and creates the list lazily) without duplicating an entry
        // for the same (src, hit) pair.
        public void AddEvidence(string source, string hit)
        {
            if (string.IsNullOrEmpty(source) || string.IsNullOrEmpty(hit)) return;
            if (!EvidenceSources.TryGetValue(source, out var lst))
            {
                lst = new List<string>();
                EvidenceSources[source] = lst;
            }
            if (!lst.Contains(hit, StringComparer.Ordinal))
                lst.Add(hit);
        }
    }

    public static partial class Analyzer
    {
        // ---------------- CC1 MSI ---------------------------------------
        // The MSI format is a compound-document containing tables. Malicious
        // installers typically exploit CustomAction type 2/18/34/50 which
        // chain DLL/EXE execution. The table names "CustomAction",
        // "InstallExecuteSequence", and property names like
        // "ASLR_NOINHERIT" show up verbatim in extracted strings when the
        // DocFile storage is opened.
        private static readonly string[] MsiBadCustomActionMarkers =
        {
            "CustomAction",
            "InstallExecuteSequence",
            "AdminExecuteSequence",
            "Type 3074",       // msidbCustomActionTypeVBScript | TypeDeferred | NoImpersonate
            "Type 1042",       // JScript
            "Type 3090",       // EXE + Deferred + NoImpersonate
            "cmd.exe /c",
            "powershell.exe",
            "-ep bypass", "-EncodedCommand",
            "rundll32",
            "regsvr32 /s",
            "mshta ",
        };

        internal static void DetectMsiCustomActions(AnalysisResult r, string text)
        {
            // Only run for MSI files to reduce false positives.
            if (r.FormatFamily?.IndexOf("MSI", StringComparison.OrdinalIgnoreCase) < 0 &&
                !r.FilePath.EndsWith(".msi", StringComparison.OrdinalIgnoreCase)) return;
            foreach (var m in MsiBadCustomActionMarkers)
                if (text.IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0)
                    r.MsiCustomActionHits.Add(m);
            if (r.MsiCustomActionHits.Count > 0)
                r.MitreTtps.Add("T1218.007"); // Msiexec
        }

        // ---------------- CC2 APPX/MSIX --------------------------------
        private static readonly string[] AppxDangerousCapabilities =
        {
            "runFullTrust",
            "allowElevation",
            "broadFileSystemAccess",
            "<rescap:Capability",
            "packageManagement",
            "confirmAppClose",
            "documentsLibrary",
            "removableStorage",
            "<Execution Level=\"administrator\"",
            "<uap4:SupportedFileTypes>", // + script ext below
        };
        internal static void DetectAppxCapabilities(AnalysisResult r, string text)
        {
            if (r.FormatFamily?.IndexOf("APPX", StringComparison.OrdinalIgnoreCase) < 0 &&
                r.FormatFamily?.IndexOf("MSIX", StringComparison.OrdinalIgnoreCase) < 0 &&
                !r.FilePath.EndsWith(".appx", StringComparison.OrdinalIgnoreCase) &&
                !r.FilePath.EndsWith(".msix", StringComparison.OrdinalIgnoreCase)) return;
            foreach (var m in AppxDangerousCapabilities)
                if (text.IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0)
                    r.AppxCapabilityHits.Add(m);
            if (r.AppxCapabilityHits.Any(h => h.Contains("runFullTrust", StringComparison.OrdinalIgnoreCase)))
                r.MitreTtps.Add("T1055");
        }

        // ---------------- CC3 Mach-O -----------------------------------
        private static readonly string[] MachOSuspiciousLoadCommands =
        {
            "LC_ENCRYPTION_INFO",
            "LC_DYLD_INFO_ONLY",
            "LC_CODE_SIGNATURE",
            "LC_LOAD_DYLINKER",
            "LC_RPATH",
            "@executable_path",
            "@rpath",
            "__RESTRICT",    // absence ⇒ DYLD_INSERT_LIBRARIES possible
            "/usr/bin/osascript",
            "/bin/launchctl",
            "chmod +x",
        };
        internal static void DetectMachOLoadCommands(AnalysisResult r, string text)
        {
            if (r.FormatFamily?.IndexOf("Mach-O", StringComparison.OrdinalIgnoreCase) < 0) return;
            foreach (var m in MachOSuspiciousLoadCommands)
                if (text.IndexOf(m, StringComparison.Ordinal) >= 0)
                    r.MachOLoadCommandHits.Add(m);
        }

        // ---------------- CC4 ELF --------------------------------------
        private static readonly string[] ElfSuspiciousMarkers =
        {
            "DT_RPATH", "DT_RUNPATH",
            "/tmp/",                // dropper pattern
            "/dev/shm/",
            "LD_PRELOAD",
            "ptrace",               // anti-debug
            "/proc/self/maps",
            "chmod 777",
            "setsid",
            "nohup ",
            "crontab -",
            "wget http", "curl -s http",
            "/etc/systemd/system/",
            "/etc/rc.local",
            "/etc/cron.",
        };
        internal static void DetectElfDynamic(AnalysisResult r, string text)
        {
            if (r.FormatFamily?.IndexOf("ELF", StringComparison.OrdinalIgnoreCase) < 0) return;
            foreach (var m in ElfSuspiciousMarkers)
                if (text.IndexOf(m, StringComparison.Ordinal) >= 0)
                    r.ElfDynamicHits.Add(m);
            if (r.ElfDynamicHits.Any(h => h.StartsWith("/etc/cron") || h == "crontab -"))
                r.MitreTtps.Add("T1053.003");
            if (r.ElfDynamicHits.Any(h => h == "LD_PRELOAD"))
                r.MitreTtps.Add("T1574.006");
        }

        // ---------------- CC5 VBA / Office -----------------------------
        private static readonly string[] VbaDangerousTokens =
        {
            "Auto_Open", "AutoOpen", "Document_Open", "Workbook_Open",
            "AutoExec", "AutoExit", "Document_Close", "Workbook_Activate",
            "Shell(", "CreateObject(",
            "Wscript.Shell", "WScript.Shell",
            "ADODB.Stream", "MSXML2.XMLHTTP", "WinHttp.WinHttpRequest",
            "cmd /c",  "cmd.exe",
            "powershell", "-EncodedCommand", "-enc ",
            "GetObject(\"winmgmts", "Win32_Process",
            "URLDownloadToFile", "URLDownload",
            "CallByName", "StrReverse", "Chr(",
            "Environ(\"APPDATA\")", "Environ(\"TEMP\")",
            "ExecuteExcel4Macro", "Application.Run",
            "VBA.Shell", "Base64",
        };
        internal static void DetectVbaMacros(AnalysisResult r, string text)
        {
            bool isOffice =
                r.FilePath.EndsWith(".doc",  StringComparison.OrdinalIgnoreCase) ||
                r.FilePath.EndsWith(".docm", StringComparison.OrdinalIgnoreCase) ||
                r.FilePath.EndsWith(".xls",  StringComparison.OrdinalIgnoreCase) ||
                r.FilePath.EndsWith(".xlsm", StringComparison.OrdinalIgnoreCase) ||
                r.FilePath.EndsWith(".ppt",  StringComparison.OrdinalIgnoreCase) ||
                r.FilePath.EndsWith(".pptm", StringComparison.OrdinalIgnoreCase) ||
                r.FormatFamily?.IndexOf("Office", StringComparison.OrdinalIgnoreCase) >= 0 ||
                r.FormatFamily?.IndexOf("OLE",    StringComparison.OrdinalIgnoreCase) >= 0 ||
                text.IndexOf("Microsoft Office", StringComparison.Ordinal) >= 0;
            if (!isOffice) return;

            foreach (var m in VbaDangerousTokens)
                if (text.IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0)
                    r.VbaMacroHits.Add(m);
            if (r.VbaMacroHits.Any(h => h.Contains("Shell") || h.Contains("cmd") || h.Contains("powershell")))
                r.MitreTtps.Add("T1059.003");
            if (r.VbaMacroHits.Any(h => h.Contains("URLDownload") || h.Contains("MSXML2")))
                r.MitreTtps.Add("T1105");
            if (r.VbaMacroHits.Any(h => h.StartsWith("Auto") || h.Contains("Document_Open")))
                r.MitreTtps.Add("T1137.001");
        }

        // ---------------- CC6 PDF --------------------------------------
        private static readonly string[] PdfSuspiciousMarkers =
        {
            "/JavaScript", "/JS",
            "/OpenAction", "/AA",
            "/Launch",
            "/EmbeddedFile",
            "/URI", "/GoToR",
            "/SubmitForm",
            "this.exportDataObject",
            "this.getAnnots",
            "util.printd",
            "app.launchURL",
            "eval(", "unescape(", "String.fromCharCode",
        };
        internal static void DetectPdfJavaScript(AnalysisResult r, string text)
        {
            if (r.FormatFamily?.IndexOf("PDF", StringComparison.OrdinalIgnoreCase) < 0 &&
                !r.FilePath.EndsWith(".pdf", StringComparison.OrdinalIgnoreCase)) return;
            foreach (var m in PdfSuspiciousMarkers)
                if (text.IndexOf(m, StringComparison.Ordinal) >= 0)
                    r.PdfJsActionHits.Add(m);
            if (r.PdfJsActionHits.Any(h => h == "/JS" || h == "/JavaScript"))
                r.MitreTtps.Add("T1204.002");
        }

        // ---------------- CC7 LNK --------------------------------------
        private static readonly string[] LnkBadCommandTokens =
        {
            "cmd.exe", "cmd /c",
            "powershell.exe", "powershell -",
            "mshta", "mshta.exe",
            "rundll32",
            "regsvr32 /s /n /u",
            "wscript", "cscript",
            "bitsadmin /transfer",
            "certutil -urlcache", "certutil -decode",
            "curl http", "wget http",
            "Invoke-Expression", "IEX ",
            "-EncodedCommand", "-enc ",
            "-nop -w hidden", "-NoP -NonI",
            "hh.exe", "msiexec /i http",
        };
        internal static void DetectLnkCommands(AnalysisResult r, string text)
        {
            if (!r.FilePath.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) &&
                r.FormatFamily?.IndexOf("Link", StringComparison.OrdinalIgnoreCase) < 0) return;
            foreach (var m in LnkBadCommandTokens)
                if (text.IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0)
                    r.LnkCommandHits.Add(m);
            if (r.LnkCommandHits.Count > 0)
                r.MitreTtps.Add("T1204.002");
        }

        // ---------------- CC8 PowerShell deobfuscation ----------------
        // Encoded / heavily-obfuscated PowerShell idioms. These are
        // remarkably consistent across loaders — attackers re-use the same
        // patterns for years.
        private static readonly string[] PowerShellObfMarkers =
        {
            "FromBase64String",
            "IEX (New-Object",
            "Invoke-Expression",
            "[System.Reflection.Assembly]::Load",
            "System.Net.WebClient",
            "DownloadString(",
            "DownloadFile(",
            "New-Object System.Net.Sockets.TCPClient",
            "[Convert]::FromBase64String",
            "[Text.Encoding]::",
            "-bxor", "-join",
            "[char]", "[char[]]",
            "-replace '",
            "Add-MpPreference -ExclusionPath",
            "Set-MpPreference -DisableRealtimeMonitoring",
            "bypass -w hidden", "bypass -W hidden",
            "-nop -w 1 -c",
            "iex (",
            "Start-Process -WindowStyle Hidden",
            "Invoke-WebRequest -Uri",
        };
        internal static void DetectPowerShellObf(AnalysisResult r, string text)
        {
            bool isPsContext =
                r.FilePath.EndsWith(".ps1",  StringComparison.OrdinalIgnoreCase) ||
                r.FilePath.EndsWith(".psm1", StringComparison.OrdinalIgnoreCase) ||
                r.FilePath.EndsWith(".lnk",  StringComparison.OrdinalIgnoreCase) ||
                text.IndexOf("powershell", StringComparison.OrdinalIgnoreCase) >= 0;
            if (!isPsContext) return;
            foreach (var m in PowerShellObfMarkers)
                if (text.IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0)
                    r.PowerShellObfHits.Add(m);
            if (r.PowerShellObfHits.Any(h => h.Contains("FromBase64String") || h.StartsWith("-bxor")))
                r.MitreTtps.Add("T1027");
            if (r.PowerShellObfHits.Any(h => h.Contains("Add-MpPreference") || h.Contains("DisableRealtimeMonitoring")))
                r.MitreTtps.Add("T1562.001");
            if (r.PowerShellObfHits.Count > 0)
                r.MitreTtps.Add("T1059.001");
        }

        // ---------------- CC9 JS deobfuscation ------------------------
        private static readonly string[] JsObfMarkers =
        {
            "eval(function(p,a,c,k,e,d)",         // packer.js
            "_0x",                                 // hexed vars (obfuscator.io)
            "String.fromCharCode(",
            "charCodeAt(",
            "atob(",                               // base64 decode
            "escape(\"%u",                         // JS/aaencode
            "ﾟωﾟﾉ",                               // aaencode / jjencode
            "(o^_^o)",
            "new Function(\"return ",
            "window['eval']",
            "document['write']",
            "unescape(",
            "eval(atob(",
        };
        internal static void DetectJsObfuscation(AnalysisResult r, string text)
        {
            bool js =
                r.FilePath.EndsWith(".js",  StringComparison.OrdinalIgnoreCase) ||
                r.FilePath.EndsWith(".mjs", StringComparison.OrdinalIgnoreCase) ||
                r.FilePath.EndsWith(".html",StringComparison.OrdinalIgnoreCase) ||
                r.FilePath.EndsWith(".htm", StringComparison.OrdinalIgnoreCase) ||
                text.IndexOf("<script", StringComparison.OrdinalIgnoreCase) >= 0;
            if (!js) return;
            foreach (var m in JsObfMarkers)
                if (text.IndexOf(m, StringComparison.Ordinal) >= 0)
                    r.JsObfuscationHits.Add(m);
            if (r.JsObfuscationHits.Count > 0) r.MitreTtps.Add("T1027");
        }

        // ---------------- CC10 HTA / CHM -------------------------------
        internal static void DetectHtaChm(AnalysisResult r, string text)
        {
            bool hta = r.FilePath.EndsWith(".hta", StringComparison.OrdinalIgnoreCase) ||
                       text.IndexOf("<HTA:APPLICATION", StringComparison.OrdinalIgnoreCase) >= 0;
            bool chm = r.FilePath.EndsWith(".chm", StringComparison.OrdinalIgnoreCase) ||
                       text.StartsWith("ITSF");
            if (!hta && !chm) return;
            string[] markers = hta
                ? new[] { "<HTA:APPLICATION", "WScript.Shell", "ActiveXObject", "cmd /c", "powershell", "WinExec", "ShellExecute" }
                : new[] { "ITSF", "iexplore.exe", "shortcut", "command=", "param name=\"Command\"" };
            foreach (var m in markers)
                if (text.IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0)
                    r.HtaChmHits.Add(m);
            if (r.HtaChmHits.Count > 0) r.MitreTtps.Add("T1218.005"); // Mshta
        }

        // ---------------- CC11 OneNote ---------------------------------
        internal static void DetectOneNoteEmbeds(AnalysisResult r, string text, byte[] prefix)
        {
            bool one = r.FilePath.EndsWith(".one", StringComparison.OrdinalIgnoreCase) ||
                       (prefix != null && prefix.Length > 8 &&
                        prefix[0] == 0xE4 && prefix[1] == 0x52 && prefix[2] == 0x5C && prefix[3] == 0x7B);
            if (!one) return;
            string[] tokens =
            {
                "FileDataStore",                 // container GUID prefix
                "{BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}", // FileDataStoreObject root
                ".exe", ".dll", ".cmd", ".bat", ".vbs", ".js", ".lnk", ".iso", ".hta",
                "MZ",                            // embedded PE header
                "D0 CF 11 E0",                   // OLE header
                "PK" + "\x03\x04",               // zip header
            };
            foreach (var m in tokens)
                if (text.IndexOf(m, StringComparison.Ordinal) >= 0)
                    r.OneNoteEmbedHits.Add(m);
            if (r.OneNoteEmbedHits.Count > 0) r.MitreTtps.Add("T1204.002");
        }

        // ---------------- CC12 ClickOnce -------------------------------
        internal static void DetectClickOnceManifest(AnalysisResult r, string text)
        {
            bool co = r.FilePath.EndsWith(".application", StringComparison.OrdinalIgnoreCase) ||
                      r.FilePath.EndsWith(".manifest",    StringComparison.OrdinalIgnoreCase) ||
                      text.IndexOf("<asmv2:deployment",    StringComparison.OrdinalIgnoreCase) >= 0;
            if (!co) return;
            string[] markers =
            {
                "<deployment install=\"true\"",
                "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">",
                "<assemblyIdentity name=\"", // + check for powershell/cmd below
                "<dependentAssembly",
                "minimumRequiredVersion=\"0.0.0.0\"",
                "<subscription>",
                "<expiration maximumAge=",
                "<update>",
                "codebase=\"http://",           // http over update
            };
            foreach (var m in markers)
                if (text.IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0)
                    r.ClickOnceHits.Add(m);
            if (r.ClickOnceHits.Any(h => h.Contains("codebase=\"http://")))
                r.MitreTtps.Add("T1195.002");
        }

        // ---------------- CC13 Lua (SA-MP / GTA loaders & stealers) -----
        //
        // We mirror the JS reference detector that ships with the web UI:
        // a fixed table of (threat_type, required_signatures[]). A rule
        // fires only when *every* signature in its group is present in
        // the file content read as a binary-preserving 8-bit string (ISO
        // 8859-1 / Latin-1). This is critical because real-world payloads
        // we want to catch live inside Lua scripts that include CR/LF,
        // backslash-escaped paths, and base64/PE blobs — a strict UTF-8
        // decode would corrupt them.
        //
        // Each entry is a single threat-class label that the UI surfaces
        // verbatim. Signatures are matched ordinal / case-sensitively
        // because that's what the source samples actually contain (e.g.
        // 'LoadLibraryA' is a Windows API name, not free text).
        internal static readonly (string Type, string[] Signatures)[] LuaThreatRules =
        {
            (
                "Загрузчик лоадера (gtaweap4.saa)",
                new[] { "gtaweap4.saa", "loadDynamicLibrary", "_sendCommand", "callFunction" }
            ),
            (
                "Загрузчик стиллера (AntiCrashInfo.asi)",
                new[]
                {
                    "raw.githubusercontent.com",
                    "/zalupaFM/versioncheck/refs/heads/main/ver",
                    "barssign", "update.bin",
                    @"C:\Users\nzx3r\Desktop",
                }
            ),
            (
                "Загрузчик стиллера (client.asi)",
                new[] { "_sendCommand", "client.asi", "nzx3r", "LoadLibraryA", "GetProcAddress" }
            ),
            (
                "Стиллер (AntiCrashInfo.asi)",
                new[]
                {
                    "OnDialogResponse", "GTASA_CustomExec_Mutex_",
                    "barssign", "hooks.cpp", "CSampStealerR3",
                }
            ),
            (
                "Загрузчик (data/*.exe)",
                new[] { "CSampStealerR", "nzx3r", "LoadLibraryA", "GetProcAddress", ".exe" }
            ),
        };

        // Decoded file payload (binary-preserving Latin-1) used by the Lua
        // detector. Callers pass the raw prefix bytes; we ToString() them
        // once as ISO-8859-1 so signature matching is ordinal byte-for-byte
        // and CR/LF / NUL bytes / high-bit bytes are preserved (these are
        // critical inside Lua-loaded ASI/exe payloads).
        internal static void DetectLuaThreats(AnalysisResult r, byte[] rawBytes)
        {
            bool gate = r.FilePath.EndsWith(".lua", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(r.FormatFamily, "Script-LUA", StringComparison.Ordinal);
            if (!gate) return;
            if (rawBytes == null || rawBytes.Length == 0) return;

            // ISO-8859-1 is a 1:1 byte->char mapping — no exceptions on
            // high-bit bytes, no normalisation. Equivalent to the
            // 'iso-8859-1' TextDecoder used by the reference JS scanner.
            var haystack = System.Text.Encoding.Latin1.GetString(rawBytes);

            foreach (var (type, sigs) in LuaThreatRules)
            {
                bool all = true;
                for (int i = 0; i < sigs.Length; i++)
                {
                    if (haystack.IndexOf(sigs[i], StringComparison.Ordinal) < 0)
                    {
                        all = false;
                        break;
                    }
                }
                if (all && !r.LuaThreatHits.Contains(type, StringComparer.Ordinal))
                    r.LuaThreatHits.Add(type);
            }

            if (r.LuaThreatHits.Count > 0)
            {
                // Lua loaders / stealers run as user-space code in a host
                // process — T1059 (script execution) + T1105 (remote payload
                // ingress, for the github.com / update.bin URLs).
                r.MitreTtps.Add("T1059");
                r.MitreTtps.Add("T1105");
            }
        }

        // Scoring contribution capped at +45. Each format ceiling keeps a
        // single verbose sample from dominating the score.
        internal static int FormatDetectorsBonus(AnalysisResult r)
        {
            int b = 0;
            b += Math.Min(10, r.MsiCustomActionHits.Count * 3);
            b += Math.Min(10, r.AppxCapabilityHits.Count * 3);
            b += Math.Min(6,  r.MachOLoadCommandHits.Count * 2);
            b += Math.Min(8,  r.ElfDynamicHits.Count * 2);
            b += Math.Min(15, r.VbaMacroHits.Count * 3);
            b += Math.Min(15, r.PdfJsActionHits.Count * 3);
            b += Math.Min(15, r.LnkCommandHits.Count * 4);
            b += Math.Min(15, r.PowerShellObfHits.Count * 3);
            b += Math.Min(10, r.JsObfuscationHits.Count * 3);
            b += Math.Min(12, r.HtaChmHits.Count * 3);
            b += Math.Min(12, r.OneNoteEmbedHits.Count * 4);
            b += Math.Min(8,  r.ClickOnceHits.Count * 2);
            // Lua hits represent a confirmed-malicious threat-class label,
            // not a loose IOC, so each hit is worth a flat +20 (capped).
            b += Math.Min(45, r.LuaThreatHits.Count * 20);
            // B9 — modern stealer pattern bumps. Each cluster is
            // medium-fidelity on its own; the decisive floors in
            // Score() handle the cross-signal combination.
            b += Math.Min(15, r.ClickFixCaptchaHits.Count * 5);
            b += Math.Min(15, r.LummaConfigHits.Count     * 5);
            b += Math.Min(15, r.BrowserExtTheftHits.Count * 4);
            b += Math.Min(12, r.MfaAppTheftHits.Count     * 4);
            b += Math.Min(10, r.StealerPostBodyHits.Count * 3);
            return Math.Min(70, b);
        }
    }
}
