// BB11-BB26: second wave of detection modules. Implemented as additional partials of
// `Analyzer` / `AnalysisResult`. See Detectors.cs for BB1-BB10.
//
//  BB11 DetectResourceStego            — suspicious payloads hidden in PE resources
//  BB12 DetectOverlayPayload           — classify overlay (PE / ZIP / other) and score accordingly
//  BB13 DetectKnownPackers             — Themida / VMProtect / Enigma / MPRESS / ASPack / PECompact
//  BB14 DetectDotNetObfuscators       — ConfuserEx / SmartAssembly / .NET Reactor / Babel / ...
//  BB15 DetectClipboardHijack          — clipboard API combo + wallet regex
//  BB16 DetectKeylogger                — keystroke capture primitives
//  BB17 DetectScreenGrabber            — GDI screenshot pipeline
//  BB18 DetectStealerMutexes           — characteristic mutex names
//  BB19 ComputeStringCrossReferences   — attribute hits to PE sections (.text vs .data)
//  BB20 DetectCredentialFilePaths      — Thunderbird / FileZilla / Credentials / OpenVPN / SSH
//  BB21 DetectCryptoWalletPaths        — Electrum / Exodus / Atomic / Guarda / Metamask ext.
//  BB22 DetectTelegramDesktopTheft     — tdata path + D877F783D5D3EF8C magic
//  BB23 DetectDiscordLevelDbTheft      — leveldb path + .ldb + token regex
//  BB24 DetectTwoFactorTheft           — Authy / Authenticator / Steam SSFN / Bethesda
//  BB25 DetectRansomwarePatterns       — file extension renames + ransom-note naming + shadow delete
//  BB26 DetectDestructivePayloads      — event-log clear / BCD / USN journal / raw-disk writes

namespace AntiStealerOneExe
{
    public sealed partial class AnalysisResult
    {
        public List<string> ResourceStegoHits { get; set; } = new();
        public string OverlayClassification { get; set; } = "";
        public List<string> KnownPackerHits { get; set; } = new();
        public List<string> DotNetObfuscatorHits { get; set; } = new();
        public List<string> ClipboardHijackHits { get; set; } = new();
        public List<string> KeyloggerHits { get; set; } = new();
        public List<string> ScreenGrabberHits { get; set; } = new();
        public List<string> StealerMutexHits { get; set; } = new();
        public Dictionary<string, string> StringCrossRefs { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> CredentialFilePathHits { get; set; } = new();
        public List<string> CryptoWalletPathHits { get; set; } = new();
        public List<string> TelegramDesktopTheftHits { get; set; } = new();
        public List<string> DiscordLevelDbTheftHits { get; set; } = new();
        public List<string> TwoFactorTheftHits { get; set; } = new();
        public List<string> RansomwareHits { get; set; } = new();
        public List<string> DestructivePayloadHits { get; set; } = new();
    }

    public static partial class Analyzer
    {
        // ---------------------------------------------------------------------
        // BB11: resource-stego. Some stealers embed a secondary PE or a ZIP
        // archive inside a .rsrc entry disguised as an ICON / PNG / BITMAP /
        // RCDATA. If we see a resource whose first bytes look like `MZ` / `PK`
        // or which has anomalous entropy, surface it.
        // The analyser already populates `ResourceSummaries` and measures
        // per-section entropy; we reuse those artefacts.
        // ---------------------------------------------------------------------
        internal static void DetectResourceStego(AnalysisResult r)
        {
            // Two signals we can compute without re-parsing the PE:
            //  1) the .rsrc section shows very high entropy (>=7.5), which is inconsistent with
            //     plain icons/version-info and suggests an encrypted secondary payload.
            //  2) the analyzer picked up a second "This program cannot be run in DOS mode" stub
            //     (i.e. a PE embedded inside a PE) — this is surfaced in StringHits already.
            foreach (var kv in r.SectionEntropy)
            {
                if (kv.Key.IndexOf("rsrc", StringComparison.OrdinalIgnoreCase) >= 0 && kv.Value >= 7.5)
                    r.ResourceStegoHits.Add($".rsrc entropy={kv.Value:0.00} (encrypted payload likely)");
            }
            int dosStubs = 0;
            foreach (var s in r.StringHits)
                if (s.IndexOf("This program cannot be run in DOS mode", StringComparison.Ordinal) >= 0)
                    dosStubs++;
            if (dosStubs >= 2)
                r.ResourceStegoHits.Add($"{dosStubs} DOS-stubs → embedded PE in resources");

            if (r.ResourceStegoHits.Count > 0) r.MitreTtps.Add("T1027.002"); // Software Packing
        }

        // ---------------------------------------------------------------------
        // BB12: overlay classification.
        // `OverlaySize` is populated by `CalculateOverlaySize` already; here we
        // just label it. Analyzer also reads the overlay prefix into the
        // analysis text, so we can detect MZ/PK/gzip/ELF/7z/RAR magic there.
        // ---------------------------------------------------------------------
        internal static void DetectOverlayPayload(AnalysisResult r, string analysisText)
        {
            if (r.OverlaySize <= 0) return;
            // Look for magic-byte markers in the already-extracted text (note: text is ASCII
            // strings, not raw bytes — we rely on the fact that `MZ`, `PK\x03\x04`, `7z\xbc\xaf'
            // produce recognisable ASCII prefixes when string-extracted).
            if (analysisText.IndexOf("!This program cannot be run in DOS mode", StringComparison.Ordinal) >= 0)
                r.OverlayClassification = $"embedded PE ({r.OverlaySize} bytes)";
            else if (analysisText.IndexOf("7-Zip", StringComparison.OrdinalIgnoreCase) >= 0 && r.OverlaySize > 1024)
                r.OverlayClassification = $"7-Zip archive overlay ({r.OverlaySize} bytes)";
            else if (r.OverlaySize >= 128 * 1024)
                r.OverlayClassification = $"large opaque overlay ({r.OverlaySize} bytes)";
            if (!string.IsNullOrEmpty(r.OverlayClassification))
                r.MitreTtps.Add("T1027.009"); // Embedded Payloads
        }

        // ---------------------------------------------------------------------
        // BB13: extended packer signature detection. Beyond UPX (already handled),
        // identify commercial protectors by section names + string markers.
        // ---------------------------------------------------------------------
        private static readonly (string Name, string[] SectionNames, string[] StringMarkers)[] PackerSignatures =
        {
            ("Themida",     new[] { ".themida", ".tsustack", ".tsuarch" }, new[] { "Themida", "Oreans", "WinLicense" }),
            ("VMProtect",   new[] { ".vmp0", ".vmp1", ".vmp2" },           new[] { "VMProtect", "vmp-core" }),
            ("Enigma",      new[] { ".enigma1", ".enigma2" },              new[] { "Enigma Protector" }),
            ("MPRESS",      new[] { ".MPRESS1", ".MPRESS2" },              new[] { "MPRESS" }),
            ("ASPack",      new[] { ".aspack", ".adata" },                 new[] { "ASPack", "aspack" }),
            ("PECompact",   new[] { "pec1", "pec2" },                      new[] { "PECompact", "PEC2" }),
            ("ASProtect",   new[] { ".aspr", ".adata" },                   new[] { "ASProtect" }),
            ("Petite",      new[] { ".petite" },                           new[] { "petite" }),
            ("Obsidium",    new[] { ".obsid" },                            new[] { "Obsidium" }),
            ("Upack",       new[] { ".Upack" },                            new[] { "Upack" }),
        };

        internal static void DetectKnownPackers(AnalysisResult r, string analysisText)
        {
            foreach (var (name, secs, markers) in PackerSignatures)
            {
                bool hit = r.SectionNames.Any(sn => secs.Any(s => sn.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0))
                        || markers.Any(m => analysisText.IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0);
                if (hit) r.KnownPackerHits.Add(name);
            }
            if (r.KnownPackerHits.Count > 0) r.MitreTtps.Add("T1027.002");
        }

        // ---------------------------------------------------------------------
        // BB14: .NET obfuscator fingerprints. These live as string markers in
        // the managed metadata; on a .NET sample we surface any we recognise.
        // ---------------------------------------------------------------------
        private static readonly (string Name, string[] Markers)[] DotNetObfuscatorMarkers =
        {
            ("ConfuserEx",      new[] { "ConfusedByAttribute", "ConfuserEx", "_CorExeMain\0Confus" }),
            ("SmartAssembly",   new[] { "SmartAssembly.Attributes", "PoweredByAttribute" }),
            (".NET Reactor",    new[] { "Reactor.NET", "netz_pe", "{Eziriz}" }),
            ("Obfuscar",        new[] { "Obfuscar.Gui", "ObfuscationAttribute" }),
            ("Babel Obfuscator", new[] { "Babel.ObfuscatorAttribute" }),
            ("DotNetPatcher",   new[] { "DotNetPatcher", "dNpHelper" }),
            ("Eazfuscator",     new[] { "Eazfuscator.NET" }),
            ("Crypto Obfuscator", new[] { "CryptoObfuscator" }),
        };

        internal static void DetectDotNetObfuscators(AnalysisResult r, string analysisText)
        {
            if (!r.IsDotNetLikely) return;
            foreach (var (name, markers) in DotNetObfuscatorMarkers)
            {
                if (markers.Any(m => analysisText.IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0))
                    r.DotNetObfuscatorHits.Add(name);
            }
            if (r.DotNetObfuscatorHits.Count > 0) r.MitreTtps.Add("T1027");
        }

        // ---------------------------------------------------------------------
        // BB15: clipboard hijack (clipper). High-precision signal: the combo of
        // clipboard APIs + a wallet regex/address in the same binary is a clipper.
        // ---------------------------------------------------------------------
        internal static void DetectClipboardHijack(AnalysisResult r, IReadOnlyCollection<string> imports)
        {
            bool HasApi(params string[] names) => names.Any(n => imports.Any(i => i.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0));

            bool readApis  = HasApi("OpenClipboard", "GetClipboardData");
            bool writeApis = HasApi("SetClipboardData", "EmptyClipboard");
            bool hasWalletRegexOrAddr =
                r.CryptoWalletHits.Count >= 1 ||
                r.StringHits.Any(s => s.Contains("^[13]{1}", StringComparison.Ordinal)        // BTC regex fragment
                                   || s.Contains("^0x[a-fA-F0-9]{40}", StringComparison.Ordinal) // ETH regex fragment
                                   || s.Contains("bc1q", StringComparison.OrdinalIgnoreCase));

            if (readApis && writeApis)
                r.ClipboardHijackHits.Add("clipboard read+write API combo");
            if (readApis && hasWalletRegexOrAddr)
            {
                r.ClipboardHijackHits.Add("clipboard read + wallet pattern in binary → clipper");
                r.MitreTtps.Add("T1115");   // Clipboard Data
                r.MitreTtps.Add("T1657");   // Financial Theft
            }
        }

        // ---------------------------------------------------------------------
        // BB16: keystroke logger. Classic API combos.
        // ---------------------------------------------------------------------
        internal static void DetectKeylogger(AnalysisResult r, IReadOnlyCollection<string> imports)
        {
            bool Has(string n) => imports.Any(i => i.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0);
            if (Has("SetWindowsHookEx") && (Has("CallNextHookEx") || Has("GetForegroundWindow")))
                r.KeyloggerHits.Add("SetWindowsHookEx (WH_KEYBOARD_LL)");
            if (Has("GetAsyncKeyState") && Has("GetForegroundWindow"))
                r.KeyloggerHits.Add("GetAsyncKeyState polling loop");
            if (Has("GetRawInputData") && Has("RegisterRawInputDevices"))
                r.KeyloggerHits.Add("Raw Input device capture");
            if (r.KeyloggerHits.Count > 0) r.MitreTtps.Add("T1056.001");
        }

        // ---------------------------------------------------------------------
        // BB17: screen grabber. GDI screenshot pipeline.
        // ---------------------------------------------------------------------
        internal static void DetectScreenGrabber(AnalysisResult r, IReadOnlyCollection<string> imports)
        {
            bool Has(string n) => imports.Any(i => i.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0);
            if (Has("BitBlt") && Has("CreateCompatibleDC") && Has("GetDC"))
                r.ScreenGrabberHits.Add("GDI BitBlt pipeline");
            if (Has("GdipCreateBitmapFromHBITMAP") || Has("GdipSaveImageToFile"))
                r.ScreenGrabberHits.Add("GDI+ bitmap save");
            if (Has("CreateDIBSection") && Has("StretchBlt"))
                r.ScreenGrabberHits.Add("DIB stretch capture");
            if (r.ScreenGrabberHits.Count > 0) r.MitreTtps.Add("T1113");
        }

        // ---------------------------------------------------------------------
        // BB18: stealer mutex names. Public research on RedLine/Vidar/Raccoon
        // and friends lists a handful of characteristic mutex strings.
        // ---------------------------------------------------------------------
        private static readonly string[] StealerMutexSubstrings =
        {
            "Global\\M_4e8d9c3a", "Global\\Stealer-", "Global\\RedLine",
            "Global\\Lumma", "Global\\RisePro", "Global\\VidarMutex",
            "RNG-Mutex-", "Amadey_", "raccoon-", "stealc_",
            "IESQMMUTEX_0_208", // commonly abused
        };

        internal static void DetectStealerMutexes(AnalysisResult r, string analysisText)
        {
            foreach (var m in StealerMutexSubstrings)
                if (analysisText.IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0)
                    r.StealerMutexHits.Add(m);
        }

        // ---------------------------------------------------------------------
        // BB19: string cross-reference — attribute each MalwareSelfIdHit /
        // GameTargetHit to the PE section that contains it (.text / .rdata /
        // .data). Section lookup is done by scanning section raw bytes.
        // This is best-effort and skipped for non-PE samples.
        // ---------------------------------------------------------------------
        internal static void ComputeStringCrossReferences(AnalysisResult r, string path)
        {
            if (r.FormatFamily != "PE") return;
            try
            {
                // Read each section's raw bytes once, keep offsets so we can say which section the
                // indicator lives in. We cap per-section read at 8 MB to protect against huge binaries.
                using var fs = File.OpenRead(path);
                using var pe = new System.Reflection.PortableExecutable.PEReader(fs);
                var headers = pe.PEHeaders;
                var sectionData = new List<(string Name, byte[] Bytes)>(headers.SectionHeaders.Length);
                foreach (var s in headers.SectionHeaders)
                {
                    try
                    {
                        var data = pe.GetSectionData(s.VirtualAddress).GetContent().ToArray();
                        if (data.Length > 8 * 1024 * 1024) Array.Resize(ref data, 8 * 1024 * 1024);
                        sectionData.Add((s.Name ?? "", data));
                    }
                    catch { }
                }

                void Attribute(string key)
                {
                    if (string.IsNullOrEmpty(key) || key.Length < 3 || key.Length > 200) return;
                    var needle = System.Text.Encoding.ASCII.GetBytes(key);
                    foreach (var (name, bytes) in sectionData)
                    {
                        if (IndexOfBytes(bytes, needle) >= 0)
                        {
                            r.StringCrossRefs[key] = name;
                            return;
                        }
                    }
                    // Try as UTF-16LE (common for .NET metadata / wide strings).
                    var needleW = System.Text.Encoding.Unicode.GetBytes(key);
                    foreach (var (name, bytes) in sectionData)
                    {
                        if (IndexOfBytes(bytes, needleW) >= 0)
                        {
                            r.StringCrossRefs[key] = $"{name}(wide)";
                            return;
                        }
                    }
                }

                foreach (var h in r.MalwareSelfIdHits.Take(20)) Attribute(TrimKeyword(h));
                foreach (var h in r.GameTargetHits.Take(20))    Attribute(h);
                foreach (var h in r.TelegramExfilEndpoints.Take(10)) Attribute(h);
            }
            catch { /* best-effort */ }
        }

        private static string TrimKeyword(string h)
        {
            int colon = h.IndexOf(':');
            return colon > 0 ? h.Substring(colon + 1).Trim() : h;
        }

        private static int IndexOfBytes(byte[] haystack, byte[] needle)
        {
            if (needle.Length == 0 || needle.Length > haystack.Length) return -1;
            int last = haystack.Length - needle.Length;
            for (int i = 0; i <= last; i++)
            {
                int j = 0;
                while (j < needle.Length && haystack[i + j] == needle[j]) j++;
                if (j == needle.Length) return i;
            }
            return -1;
        }

        // ---------------------------------------------------------------------
        // BB20: credential file paths (non-browser).
        // ---------------------------------------------------------------------
        private static readonly string[] CredentialFilePathNeedles =
        {
            "\\Thunderbird\\Profiles",
            "\\FileZilla\\recentservers.xml",
            "\\FileZilla\\sitemanager.xml",
            "\\Microsoft\\Credentials\\",
            "\\Microsoft\\Vault\\",
            "\\Microsoft\\Protect\\",
            "\\OpenVPN\\config",
            "\\OpenVPN Connect\\profiles",
            "\\.ssh\\id_rsa",
            "\\.ssh\\id_dsa",
            "\\.ssh\\id_ecdsa",
            "\\.ssh\\id_ed25519",
            "\\.ssh\\known_hosts",
            "\\PuTTY\\Sessions",
            "\\WinSCP.ini",
            "\\RDCMan.settings",
            "\\AppData\\Roaming\\Cyberduck",
            "\\.aws\\credentials",
            "\\.aws\\config",
            "\\AppData\\Roaming\\Pidgin\\.purple\\accounts.xml",
            "\\AppData\\Roaming\\MirandaNG",
            "\\AppData\\Roaming\\Psi",
        };

        internal static void DetectCredentialFilePaths(AnalysisResult r, string analysisText)
        {
            foreach (var p in CredentialFilePathNeedles)
                if (analysisText.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0)
                    r.CredentialFilePathHits.Add(p);
            if (r.CredentialFilePathHits.Count > 0)
            {
                r.MitreTtps.Add("T1552.001"); // Credentials In Files
                r.MitreTtps.Add("T1555");
            }
        }

        // ---------------------------------------------------------------------
        // BB21: crypto-wallet paths. Complementary to CryptoWalletHits (which
        // surfaces wallet addresses): here we look for file-system paths
        // pointing at desktop-wallet stores.
        // ---------------------------------------------------------------------
        private static readonly string[] CryptoWalletPathNeedles =
        {
            "\\Electrum\\wallets",
            "\\Electrum-LTC\\wallets",
            "\\Exodus\\exodus.wallet",
            "\\Exodus\\seed.seco",
            "\\Atomic\\Local Storage",
            "\\Atomic\\IndexedDB",
            "\\Guarda\\Local Storage",
            "\\WalletWasabi\\Client\\Wallets",
            "\\Ethereum\\keystore",
            "\\Bitcoin\\wallet.dat",
            "\\Litecoin\\wallet.dat",
            "\\Dash\\wallet.dat",
            "\\Monero\\wallets",
            "\\Zcash\\wallets",
            "\\Jaxx\\Local Storage",
            "\\Coinomi\\Coinomi\\wallets",
            "nkbihfbeogaeaoehlefnkodbefgpgknn", // Metamask Chrome extension ID
            "ejbalbakoplchlghecdalmeeeajnimhm", // Metamask Edge
            "fhbohimaelbohpjbbldcngcnapndodjp", // Binance Wallet
            "bfnaelmomeimhlpmgjnjophhpkkoljpa", // Phantom
        };

        internal static void DetectCryptoWalletPaths(AnalysisResult r, string analysisText)
        {
            foreach (var p in CryptoWalletPathNeedles)
                if (analysisText.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0)
                    r.CryptoWalletPathHits.Add(p);
            if (r.CryptoWalletPathHits.Count > 0)
            {
                r.MitreTtps.Add("T1657"); // Financial Theft
                r.MitreTtps.Add("T1552.001");
            }
        }

        // ---------------------------------------------------------------------
        // BB22: Telegram Desktop tdata theft.
        // The tdata folder + magic "D877F783D5D3EF8C" key_data filename prefix
        // + "key_datas" are hard signals.
        // ---------------------------------------------------------------------
        internal static void DetectTelegramDesktopTheft(AnalysisResult r, string analysisText)
        {
            var needles = new[]
            {
                "Telegram Desktop\\tdata",
                "D877F783D5D3EF8C",   // tdata key magic
                "key_datas",
                "\\tdata\\usertag",
                "\\tdata\\settings",
            };
            foreach (var n in needles)
                if (analysisText.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0)
                    r.TelegramDesktopTheftHits.Add(n);
            if (r.TelegramDesktopTheftHits.Count > 0)
            {
                r.MitreTtps.Add("T1005");   // Data from Local System
                r.MitreTtps.Add("T1555");
            }
        }

        // ---------------------------------------------------------------------
        // BB23: Discord LevelDB session-token theft.
        // ---------------------------------------------------------------------
        internal static void DetectDiscordLevelDbTheft(AnalysisResult r, string analysisText)
        {
            var needles = new[]
            {
                "\\discord\\Local Storage\\leveldb",
                "\\discordcanary\\Local Storage\\leveldb",
                "\\discordptb\\Local Storage\\leveldb",
                ".ldb",
                "dQw4w9WgXcQ",                        // Discord-token encrypted prefix (well-known)
                "mfa.",                                // Discord MFA token prefix
                "\\Discord\\Local Storage",
            };
            foreach (var n in needles)
                if (analysisText.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0)
                    r.DiscordLevelDbTheftHits.Add(n);
            if (r.DiscordLevelDbTheftHits.Count > 0)
            {
                r.MitreTtps.Add("T1528"); // Steal Application Access Token
            }
        }

        // ---------------------------------------------------------------------
        // BB24: 2FA / session-token theft. Authy / Microsoft Authenticator /
        // Steam SSFN (remember-me) files / Bethesda.
        // ---------------------------------------------------------------------
        internal static void DetectTwoFactorTheft(AnalysisResult r, string analysisText)
        {
            var needles = new[]
            {
                "\\Authy Desktop\\",
                "\\Authy\\Local Storage",
                "\\Microsoft\\Authenticator",
                "ssfn",
                "\\Steam\\config\\loginusers.vdf",
                "\\Steam\\ssfn",
                "\\Bethesda.net Launcher\\",
                "\\Epic\\EpicGamesLauncher\\Saved\\Config",
                "\\Riot Games\\Riot Client\\Data",
            };
            foreach (var n in needles)
                if (analysisText.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0)
                    r.TwoFactorTheftHits.Add(n);
            if (r.TwoFactorTheftHits.Count > 0)
            {
                r.MitreTtps.Add("T1539"); // Steal Web Session Cookie (closest TTP for session token theft)
                r.MitreTtps.Add("T1528");
            }
        }

        // ---------------------------------------------------------------------
        // BB25: ransomware indicators. Three patterns:
        //   1) shadow-copy deletion / recovery inhibition
        //   2) ransom-note filenames
        //   3) bulk file-extension renaming (appended ".locked" / ".crypted")
        // ---------------------------------------------------------------------
        internal static void DetectRansomwarePatterns(AnalysisResult r, string analysisText)
        {
            bool Has(string n) => analysisText.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0;

            if (Has("vssadmin delete shadows") || Has("wmic shadowcopy delete") ||
                Has("bcdedit /set {default} recoveryenabled No") || Has("bcdedit /set {default} bootstatuspolicy ignoreallfailures") ||
                Has("wbadmin delete catalog"))
            {
                r.RansomwareHits.Add("recovery-inhibition commands");
                r.MitreTtps.Add("T1490");
            }

            var noteNames = new[]
            {
                "READ_ME.txt", "READ-ME.txt", "DECRYPT_INSTRUCTIONS", "HOW_TO_DECRYPT",
                "!!_READ_ME_!!", "HOW_TO_RECOVER", "RESTORE_FILES_INFO", "RECOVERY.txt",
                "WANNACRY_README", "_HELP_instructions.txt",
            };
            foreach (var n in noteNames)
                if (Has(n)) r.RansomwareHits.Add($"ransom-note: {n}");

            var exts = new[] { ".locked", ".crypted", ".encrypted", ".crypt", ".enc", ".pay2key", ".readme", ".lockbit" };
            int extMatches = exts.Count(e => Has(e));
            if (extMatches >= 2) r.RansomwareHits.Add($"{extMatches} ransomware extension markers");

            if (r.RansomwareHits.Count > 0) r.MitreTtps.Add("T1486"); // Data Encrypted for Impact
        }

        // ---------------------------------------------------------------------
        // BB26: destructive payloads. Event-log clearing, BCD tampering, USN
        // journal deletion, raw-disk write (MBR).
        // ---------------------------------------------------------------------
        internal static void DetectDestructivePayloads(AnalysisResult r, string analysisText, IReadOnlyCollection<string> imports)
        {
            bool Has(string n) => analysisText.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0;
            bool HasApi(string n) => imports.Any(i => i.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0);

            if (Has("wevtutil cl") || Has("wevtutil.exe cl"))
            {
                r.DestructivePayloadHits.Add("Windows Event-Log clearing (wevtutil cl)");
                r.MitreTtps.Add("T1070.001");
            }
            if (Has("bcdedit") && (Has("/set") || Has("recoveryenabled")))
            {
                r.DestructivePayloadHits.Add("Boot Configuration Data tampering");
                r.MitreTtps.Add("T1490");
            }
            if (Has("fsutil usn deletejournal"))
            {
                r.DestructivePayloadHits.Add("USN journal deletion");
                r.MitreTtps.Add("T1070");
            }
            if (Has("\\\\.\\PhysicalDrive") || Has("\\\\.\\PHYSICALDRIVE"))
            {
                if (HasApi("CreateFile") && HasApi("WriteFile"))
                {
                    r.DestructivePayloadHits.Add("Raw disk write (PhysicalDrive)");
                    r.MitreTtps.Add("T1561.002"); // Disk Structure Wipe
                }
                else
                {
                    r.DestructivePayloadHits.Add("raw disk path reference");
                }
            }
            if (Has("format C:") || Has("format c:"))
                r.DestructivePayloadHits.Add("format C: reference");
        }

        // Aggregate score bonus from BB11..BB26.
        internal static int AdvancedDetectionBonus2(AnalysisResult r)
        {
            int b = 0;
            b += Math.Min(20, r.ResourceStegoHits.Count * 8);
            if (!string.IsNullOrEmpty(r.OverlayClassification)) b += 5;
            b += Math.Min(10, r.KnownPackerHits.Count * 6);                 // packers raise suspicion but aren't decisive
            b += Math.Min(8,  r.DotNetObfuscatorHits.Count * 4);
            b += Math.Min(25, r.ClipboardHijackHits.Count * 10);            // clipper combo is decisive
            b += Math.Min(20, r.KeyloggerHits.Count * 8);
            b += Math.Min(15, r.ScreenGrabberHits.Count * 6);
            b += Math.Min(20, r.StealerMutexHits.Count * 10);
            b += Math.Min(20, r.CredentialFilePathHits.Count * 4);
            b += Math.Min(25, r.CryptoWalletPathHits.Count * 6);
            b += Math.Min(20, r.TelegramDesktopTheftHits.Count * 8);
            b += Math.Min(20, r.DiscordLevelDbTheftHits.Count * 8);
            b += Math.Min(15, r.TwoFactorTheftHits.Count * 6);
            b += Math.Min(35, r.RansomwareHits.Count * 10);                 // ransomware → massive bump
            b += Math.Min(35, r.DestructivePayloadHits.Count * 12);
            return Math.Min(80, b);
        }
    }
}
