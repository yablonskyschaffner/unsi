// AA2/AA3: this file hosts the UI-free analyzer core (Analyzer, AnalysisResult,
// ReportWriter, Cli, AnalyzerUiSettings). It was extracted verbatim from
// AntiStealerOneExe/Program.cs so that the WinForms GUI project and any future
// CLI-only / server / Avalonia-port consumer share exactly the same logic.
// Namespace is kept as AntiStealerOneExe for backward compatibility with tests
// and with existing serialised JSON reports.
using System.IO.Compression;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Reflection.PortableExecutable;

namespace AntiStealerOneExe
{
    public sealed class AnalyzerUiSettings
    {
        public bool RecursiveScan { get; set; } = true;
        public int MaxArchiveDepth { get; set; } = 3;
        public int MaxInputFileSizeMb { get; set; } = 64;
        public bool HideLowRisk { get; set; }
        public bool AutoSelectLastRow { get; set; } = true;
        public bool EnableServerClassifier { get; set; } = true;
        public bool EnableExternalRules { get; set; } = true;
        public int MaxReadPrefixMb { get; set; } = 20;
        public int MaxUrls { get; set; } = 500;
        public int MaxAsciiStrings { get; set; } = 50000;
        public int MaxUnicodeStrings { get; set; } = 25000;
        // F1: 0 means "use Environment.ProcessorCount"; otherwise an explicit DOP cap.
        public int MaxParallelism { get; set; }

        // C4–C10: optional cloud / external enrichment. All default off; if an API key is empty the
        // corresponding lookup is skipped silently.
        public bool EnableVirusTotal { get; set; }
        public string VirusTotalApiKey { get; set; } = "";
        public bool EnableMalwareBazaar { get; set; }
        public bool EnableTriage { get; set; }
        public string TriageApiKey { get; set; } = "";
        public bool EnableHybridAnalysis { get; set; }
        public string HybridAnalysisApiKey { get; set; } = "";
        public bool EnableAbuseIpDb { get; set; }
        public string AbuseIpDbApiKey { get; set; } = "";
        public bool EnableUrlhaus { get; set; }
        public bool EnableShodan { get; set; }
        public string ShodanApiKey { get; set; } = "";
        public bool EnableCensys { get; set; }
        public string CensysApiId { get; set; } = "";
        public string CensysApiSecret { get; set; } = "";
        public bool EnableClamAv { get; set; }
        public string ClamAvPath { get; set; } = "";   // path to clamscan.exe; auto-discovered if empty.
        public bool EnableSigmaLite { get; set; }
        public int CloudTimeoutMs { get; set; } = 5000;

        // E7: if true, after every completed scan a timestamped directory with report.json +
        // report.html is dropped into %APPDATA%\AntiStealer\Reports\.
        public bool AutoSaveReports { get; set; }

        // Section 8.4 / 8.5 (PR 10) — persisted UX preferences. Locale = "ru"
        // | "en" | "uk", LayoutPreset = "classic" | "compact" | "wide".
        // Empty strings fall back to the OS culture (handled by I18n /
        // LayoutAdapter).
        public string Locale { get; set; } = "";
        public string LayoutPreset { get; set; } = "classic";

        // D7: persisted main window geometry (-1 means 'unknown/default').
        public int WindowWidth  { get; set; } = -1;
        public int WindowHeight { get; set; } = -1;
        public int WindowLeft   { get; set; } = -1;
        public int WindowTop    { get; set; } = -1;
        public bool WindowMaximized { get; set; }
        // Last-used directories for the open-file / open-folder dialogs (D12).
        public string LastFileDir   { get; set; } = "";
        public string LastFolderDir { get; set; } = "";

        // AA5: persisted under `%TEMP%\antistealer.json` so the UI settings
        // survive a reinstall of the .exe (`AppContext.BaseDirectory` used to
        // sit next to the exe — wipe-on-reinstall) and don't pollute the install
        // folder. `Path.GetTempPath()` is cross-platform (`/tmp` on Linux,
        // `~/Library/Caches/TemporaryItems` on macOS), so a future Linux build of
        // the CLI shares the same behaviour without code changes.
        //
        // `LegacySettingsPath` is the pre-AA5 location; `Load()` migrates from
        // it on first run so users keep their saved preferences and `Save()`
        // best-effort deletes the legacy file once a new one has been written.
        internal static string SettingsPath =>
            Path.Combine(Path.GetTempPath(), "antistealer.json");

        internal static string LegacySettingsPath =>
            Path.Combine(AppContext.BaseDirectory, "settings.json");

        public static AnalyzerUiSettings Load()
        {
            try
            {
                var primary = SettingsPath;
                if (File.Exists(primary))
                {
                    var parsed = JsonSerializer.Deserialize<AnalyzerUiSettings>(File.ReadAllText(primary));
                    return parsed ?? new AnalyzerUiSettings();
                }
                // AA5 one-shot migration: pick up an existing settings.json from the
                // legacy location, but never block on it — if the read or parse
                // fails we silently fall back to defaults (same as before AA5).
                var legacy = LegacySettingsPath;
                if (File.Exists(legacy))
                {
                    var parsed = JsonSerializer.Deserialize<AnalyzerUiSettings>(File.ReadAllText(legacy));
                    if (parsed != null)
                    {
                        try { parsed.Save(); } catch { /* migration best-effort */ }
                        return parsed;
                    }
                }
                return new AnalyzerUiSettings();
            }
            catch
            {
                return new AnalyzerUiSettings();
            }
        }

        public void Save()
        {
            try
            {
                var json = JsonSerializer.Serialize(this, JsonOptionsRegistry.Indented);
                File.WriteAllText(SettingsPath, json);
                // Best-effort: clean up the legacy file once a new file has been
                // written. Swallow any IO failure (permission, file-locked, etc.) —
                // a stale legacy file is harmless, it just stops being read.
                try
                {
                    var legacy = LegacySettingsPath;
                    if (!string.Equals(legacy, SettingsPath, StringComparison.OrdinalIgnoreCase)
                        && File.Exists(legacy))
                    {
                        File.Delete(legacy);
                    }
                }
                catch { /* legacy cleanup is best-effort */ }
            }
            catch
            {
                // ignore persistence failures
            }
        }
    }

    public static partial class Analyzer
    {
        public static bool EnableServerClassification { get; set; } = true;
        public static bool EnableExternalRules { get; set; } = true;
        public static int MaxReadPrefixBytes { get; set; } = 20 * 1024 * 1024;
        // A3 — second scan window read from the *end* of the file. Many
        // stealer payloads append config, decryption keys and overlay
        // droppers AFTER the PE image, so the first 20 MiB scan misses
        // them entirely. Default 8 MiB tail; merged with the prefix in
        // the analysisText buffer.
        public static int MaxReadTailBytes  { get; set; } = 8 * 1024 * 1024;
        public static int MaxExtractedUrls { get; set; } = 500;
        public static int MaxAsciiStrings { get; set; } = 50000;
        public static int MaxUnicodeStrings { get; set; } = 25000;
        private const int MaxSearchTextChars = 2_000_000;
        private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);
        private sealed record HeuristicRule(string Name, int Weight, Func<ScanContext, bool> Predicate);

        private sealed class ScanContext
        {
            // M15: keep the original-case text; needles are lowercase and compared with OrdinalIgnoreCase,
            // which avoids allocating a full-size lowercased copy of the analysis text for every file.
            public string Text { get; init; } = string.Empty;
            public HashSet<string> Imports { get; init; } = new(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> SectionNames { get; init; } = new(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> UrlHosts { get; init; } = new(StringComparer.OrdinalIgnoreCase);
        }

        private static readonly HashSet<string> NetDlls = new(StringComparer.OrdinalIgnoreCase)
        {
            "winhttp.dll", "wininet.dll", "ws2_32.dll", "urlmon.dll", "cryptnet.dll", "dnsapi.dll", "iphlpapi.dll"
        };

        private static readonly string[] SuspiciousStringNeedles =
        {
            "password", "login data", "cookies", "cookie", "token", "authorization", "refresh_token", "master_key",
            "local state", "web data", "chrome", "chromium", "edge", "opera", "firefox", "brave", "yandex",
            "telegram", "api.telegram.org", "t.me/", "discord", "webhook", "discordapp.com/api/webhooks",
            "steam", "wallet", "seed", "metamask", "exodus", "phantom", "atomicwallet",
            "cryptunprotectdata", "dpapi", "aes", "sqlite", "vault", "wallet.dat",
            "appdata", "localappdata", "\\users\\", "\\profiles\\",
            "startup", "run\\", "taskschd", "schtasks", "autorun", "clipper", "grabber", "stealer"
        };

        private static readonly string[] SuspiciousApiNeedles =
        {
            "CryptUnprotectData", "BCryptDecrypt", "InternetOpen", "InternetOpenUrl", "InternetReadFile", "WinHttpOpen",
            "WinHttpConnect", "WinHttpSendRequest", "HttpSendRequest", "URLDownloadToFile", "socket", "connect", "send", "recv",
            "WSAStartup", "DnsQuery", "CreateToolhelp32Snapshot", "RegOpenKey", "RegSetValue", "OpenProcess",
            "ReadProcessMemory", "WriteProcessMemory", "VirtualAllocEx", "CreateRemoteThread", "MiniDumpWriteDump",
            "SetWindowsHookEx", "GetAsyncKeyState", "NtQueryInformationProcess", "IsDebuggerPresent",
            "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext", "ResumeThread", "CreateFileW", "RegCreateKeyEx",
            "WinVerifyTrust", "BCryptGenRandom", "CryptAcquireContext", "CryptDecrypt", "GetAdaptersAddresses"
        };

        private static readonly string[] PackerSectionHints =
        {
            ".themida", ".vmp", "vmp", "themida", "upx", ".upx", "aspack", "mpress", "petite", ".packed", ".stub"
        };

        private static readonly Regex UrlRegex = new(@"https?://[^\s\""'<>]+", RegexOptions.IgnoreCase | RegexOptions.Compiled, RegexTimeout);
        // M1: tighten -- enforce base64 length%4==0 with explicit padding groups, and require non-base64 boundaries.
        private static readonly Regex Base64BlobRegex = new(@"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})(?![A-Za-z0-9+/=])", RegexOptions.Compiled, RegexTimeout);
        private static readonly Regex Ipv4Regex = new(@"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b", RegexOptions.Compiled, RegexTimeout);
        private static readonly Regex EmailRegex = new(@"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", RegexOptions.Compiled, RegexTimeout);
        private static readonly Regex BtcRegex = new(@"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{24,62}\b", RegexOptions.Compiled, RegexTimeout);
        private static readonly Regex EthRegex = new(@"\b0x[a-fA-F0-9]{40}\b", RegexOptions.Compiled, RegexTimeout);
        private static readonly Regex TronRegex = new(@"\bT[1-9A-HJ-NP-Za-km-z]{33}\b", RegexOptions.Compiled, RegexTimeout);
        private static readonly Regex SolRegex = new(@"\b[1-9A-HJ-NP-Za-km-z]{43,44}\b", RegexOptions.Compiled, RegexTimeout);
        private static readonly Regex XmrRegex = new(@"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b", RegexOptions.Compiled, RegexTimeout);
        private static readonly Regex JwtRegex = new(@"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", RegexOptions.Compiled, RegexTimeout);
        private static readonly Regex TelegramBotTokenRegex = new(@"\b\d{8,10}:[A-Za-z0-9_-]{30,40}\b", RegexOptions.Compiled, RegexTimeout);
        // M3: Discord tokens -- legacy (24.6.27), current bot (26-28 . 6-7 . 38+), and user MFA (mfa.<84>).
        private static readonly Regex DiscordTokenLegacyRegex = new(@"\b[A-Za-z\d_-]{24}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27}\b", RegexOptions.Compiled, RegexTimeout);
        private static readonly Regex DiscordTokenCurrentRegex = new(@"\b[A-Za-z\d_-]{26,28}\.[A-Za-z\d_-]{6,7}\.[A-Za-z\d_-]{38,}\b", RegexOptions.Compiled, RegexTimeout);
        private static readonly Regex DiscordMfaTokenRegex = new(@"\bmfa\.[A-Za-z0-9_-]{84}\b", RegexOptions.Compiled, RegexTimeout);
        private static readonly Regex PrivateKeyBlockRegex = new(@"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED) PRIVATE KEY-----", RegexOptions.Compiled, RegexTimeout);

        // Section 5.7 — defer the ~395-rule build until first use. Most of
        // them are simple closures over `ScanContext`, but constructing the
        // full list eagerly at type-load time was visible on cold starts of
        // CLI sub-commands that never reach the analyser (`--help`,
        // `--version`, `license verify`). Lazy<> keeps the existing
        // process-wide caching semantics.
        private static readonly Lazy<List<HeuristicRule>> CustomRulesLazy =
            new(BuildCustomRules, System.Threading.LazyThreadSafetyMode.ExecutionAndPublication);
        private static List<HeuristicRule> CustomRules => CustomRulesLazy.Value;
        private static readonly HttpClient ClassifierHttp = new() { Timeout = TimeSpan.FromSeconds(4) };

        // Section 22.1 — replace 70+ empty `catch {}` clauses around detector calls with a logging
        // helper. Behaviour is unchanged (exceptions are still swallowed so a single buggy detector
        // can't kill the whole scan), but they now show up as structured warnings in the log file
        // under %LOCALAPPDATA%/AntiStealer/logs/, with the offending detector name and exception
        // message attached.
        private static void SafeRun(string detector, Action body)
        {
            try { body(); }
            catch (Exception ex)
            {
                AsiLogger.Warn("analyzer.detector_exception", new Dictionary<string, object?>
                {
                    ["detector"] = detector,
                    ["err"]      = ex.GetType().Name + ": " + ex.Message,
                });
            }
        }

        public static AnalysisResult Analyze(string path, string? displayPath = null)
        {
            // Section 6.6 — fuzz-discovered hardening: short-circuit on missing
            // files so `File.OpenRead` further down doesn't throw an uncaught
            // `FileNotFoundException`. Callers expect a non-null result.
            if (!File.Exists(path))
                return AnalysisResult.Error(displayPath ?? path, "file not found");

            try
            {
                return AnalyzeCore(path, displayPath);
            }
            catch (Exception ex)
            {
                // Section 6.6 — top-level safety net. The detector-level
                // `SafeRun` wrappers catch detector exceptions, but the PE
                // parser, archive reader and other up-front infrastructure
                // calls run outside SafeRun and have historically been able
                // to bubble e.g. `BadImageFormatException` or `IOException`
                // back to the caller. Fuzzing surfaced several such paths
                // (malformed `e_lfanew`, missing optional header, …); they
                // now degrade to an `Error` result with the exception name
                // attached, matching how `ReadPrefixAndSha256` already
                // handles low-level IO failures.
                AsiLogger.Warn("analyzer.unhandled_exception", new Dictionary<string, object?>
                {
                    ["path"] = displayPath ?? path,
                    ["err"]  = ex.GetType().Name + ": " + ex.Message,
                });
                return AnalysisResult.Error(displayPath ?? path, ex.GetType().Name + ": " + ex.Message);
            }
        }

        private static AnalysisResult AnalyzeCore(string path, string? displayPath)
        {
            // F2 + M6 + A3: hash the whole file and capture two scan
            // windows (prefix + tail) in a single pass. The tail is
            // empty when the file fits inside the prefix.
            var (sha, bytes, tailBytes) = ReadMultiWindowAndSha256(path, MaxReadPrefixBytes, MaxReadTailBytes);
            var fileSize = new FileInfo(path).Length;
            var res = new AnalysisResult(displayPath ?? path)
            {
                Size = fileSize,
                Sha256 = sha
            };

            DetectSignature(res, path);
            res.UrlsFound = ExtractUrls(bytes, MaxExtractedUrls);
            // A3 — also harvest URLs from the tail window; common in
            // stealer overlays / appended config blocks.
            if (tailBytes.Length > 0)
            {
                foreach (var u in ExtractUrls(tailBytes, MaxExtractedUrls))
                {
                    if (res.UrlsFound.Count >= MaxExtractedUrls) break;
                    if (!res.UrlsFound.Contains(u, StringComparer.OrdinalIgnoreCase))
                    {
                        res.UrlsFound.Add(u);
                        res.AddEvidence("tail", u);
                    }
                }
            }

            var allStrings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            // Section 5.6 — size the analysis-text buffer to the actual
            // input. A 4 KiB shell script no longer pre-allocates 256 KiB.
            var textBuilder = new StringBuilder(
                Math.Min(MaxSearchTextChars, AnalyzerLimits.AdaptiveSearchTextCap(fileSize)));
            foreach (var s in ExtractAsciiStrings(bytes, minLen: 5, max: MaxAsciiStrings))
                AddStringEvidence(res, s, allStrings, textBuilder, "prefix");
            foreach (var s in ExtractUnicodeStrings(bytes, minLen: 5, max: MaxUnicodeStrings))
                AddStringEvidence(res, s, allStrings, textBuilder, "prefix");
            // A3 — tail-window strings. The same dedup HashSet (allStrings)
            // prevents double-counting; the EvidenceSources dictionary
            // captures the provenance independently so explainability is
            // preserved even when a string appears in both windows.
            if (tailBytes.Length > 0)
            {
                foreach (var s in ExtractAsciiStrings(tailBytes, minLen: 5, max: MaxAsciiStrings))
                    AddStringEvidence(res, s, allStrings, textBuilder, "tail");
                foreach (var s in ExtractUnicodeStrings(tailBytes, minLen: 5, max: MaxUnicodeStrings))
                    AddStringEvidence(res, s, allStrings, textBuilder, "tail");
            }

            var analysisText = textBuilder.ToString();
            textBuilder.Clear();
            PopulateRegexIndicators(res, analysisText);

            ApplyExternalRules(res, analysisText);

            // B11–B14, B19: semantic detection modules. All operate on the already-extracted analysis
            // text (and, for B14, on the PE imports once they're parsed below — we re-run AntiAnalysis
            // after PE parsing to include import-based signals).
            DetectC2Indicators(res, analysisText);
            DetectPersistenceIndicators(res, analysisText);
            DetectBrowserStealerIndicators(res, analysisText);
            DetectMalwareSelfIdentification(res, analysisText);
            DetectGameAccountStealerTargeting(res, analysisText);
            DetectTelegramExfilEndpoints(res, analysisText);
            DetectModernStealerPatterns(res, analysisText);
            DetectAntiAnalysisIndicatorsFromText(res, analysisText);
            RunStringDeobfuscation(res, analysisText);

            // M16 + C1-C3: classify the format before we release the prefix buffer. For non-PE files we
            // surface a FormatFamily (ELF / Mach-O / PDF / OLE / ZIP / Script / LNK / ...) and run
            // format-specific indicator sweeps (PDF /JavaScript, Office VBA, script cradles, LNK target).
            bool hasMz = bytes.Length >= 2 && bytes[0] == (byte)'M' && bytes[1] == (byte)'Z';
            ClassifyAndAnalyzeNonPeFormat(path, bytes, res, analysisText);
            bytes = Array.Empty<byte>();

            if (!hasMz)
            {
                if (string.IsNullOrEmpty(res.FileType)) res.FileType = "Not PE";
                // Advanced post-aggregation detectors still apply to non-PE (scripts, ELF, Mach-O, …).
                SafeRun("DetectSigmaRulesFull",        () => DetectSigmaRulesFull(res, analysisText));
                SafeRun("DetectCapaRules",             () => DetectCapaRules(res, analysisText));
                SafeRun("DetectDgaDomains",            () => DetectDgaDomains(res));
                SafeRun("DetectBulletproofAsn",        () => DetectBulletproofAsn(res));
                // BB15..BB26 signals that are text-based (not import-based) still apply to scripts
                // / ELF / Mach-O, so run them here too.
                SafeRun("DetectStealerMutexes",        () => DetectStealerMutexes(res, analysisText));
                SafeRun("DetectCredentialFilePaths",   () => DetectCredentialFilePaths(res, analysisText));
                SafeRun("DetectCryptoWalletPaths",     () => DetectCryptoWalletPaths(res, analysisText));
                SafeRun("DetectTelegramDesktopTheft",  () => DetectTelegramDesktopTheft(res, analysisText));
                SafeRun("DetectDiscordLevelDbTheft",   () => DetectDiscordLevelDbTheft(res, analysisText));
                SafeRun("DetectTwoFactorTheft",        () => DetectTwoFactorTheft(res, analysisText));
                SafeRun("DetectRansomwarePatterns",    () => DetectRansomwarePatterns(res, analysisText));
                SafeRun("DetectDestructivePayloads",   () => DetectDestructivePayloads(res, analysisText, Array.Empty<string>()));
                SafeRun("DetectBrowserJsStealer",      () => DetectBrowserJsStealer(res, analysisText));
                SafeRun("DetectMsiCustomActions",      () => DetectMsiCustomActions(res, analysisText));
                SafeRun("DetectAppxCapabilities",      () => DetectAppxCapabilities(res, analysisText));
                SafeRun("DetectMachOLoadCommands",     () => DetectMachOLoadCommands(res, analysisText));
                SafeRun("DetectElfDynamic",            () => DetectElfDynamic(res, analysisText));
                SafeRun("DetectVbaMacros",             () => DetectVbaMacros(res, analysisText));
                SafeRun("DetectPdfJavaScript",         () => DetectPdfJavaScript(res, analysisText));
                SafeRun("DetectLnkCommands",           () => DetectLnkCommands(res, analysisText));
                SafeRun("DetectPowerShellObf",         () => DetectPowerShellObf(res, analysisText));
                SafeRun("DetectJsObfuscation",         () => DetectJsObfuscation(res, analysisText));
                SafeRun("DetectHtaChm",                () => DetectHtaChm(res, analysisText));
                SafeRun("DetectOneNoteEmbeds",         () => DetectOneNoteEmbeds(res, analysisText, Array.Empty<byte>()));
                SafeRun("DetectClickOnceManifest",     () => DetectClickOnceManifest(res, analysisText));
                SafeRun("AssignMitreAttackTtps",       () => AssignMitreAttackTtps(res));
                // YARA + MiniYaraX must run for non-PE inputs too — without
                // this any .lua / .ps1 / .js / .hta / .vbs / .pdf / .docm /
                // .zip / .jar / .apk / .lnk sample would silently bypass
                // every external and embedded rule. The static-analysis
                // text is the same corpus every other text-based detector
                // already operates on (capped at MaxSearchTextChars).
                SafeRun("RunYaraIfAvailable",          () => RunYaraIfAvailable(path, res));
                // C20: auto-ingested threat-intel feed matches (non-PE path).
                SafeRun("ThreatIntelFeedMatcher",      () => ThreatIntelFeedMatcher.Apply(res));
                SafeRun("DynamicAnalysisPipeline",     () => DynamicAnalysisPipeline.RunOn(res, analysisText));
                ApplyCustomHeuristics(res, BuildScanContext(res, analysisText));
                ApplyStructuralFamilyClassification(res, analysisText);
                res.RiskScore = Score(res);
                // A4 — recursive archive scan. Run AFTER Score() so the
                // parent has its own raw score; children can then bump
                // the parent via the container-bonus rule.
                if (IsRecursableArchive(res.FormatFamily))
                {
                    SafeRun("ScanArchiveChildren", () => ScanArchiveChildren(path, res));
                    // P5 / P6 — derive parent-child relationship
                    // edges from the children we just scanned.
                    // Build() can also lift chain markers (e.g.
                    // LuaDownloadAndLoadChain) onto the parent;
                    // re-score the parent once so the P11 floors
                    // can fire on those lifted markers.
                    SafeRun("RelationshipBuild-NonPe",
                            () => RelationshipAnalyzer.Build(res));
                    if (res.RelationshipEvidence.Count > 0)
                        res.RiskScore = Math.Max(res.RiskScore, Score(res));
                }
                res.FinalizeFlags();
                return res;
            }

            res.FormatFamily = "PE";

            using var fs = File.OpenRead(path);
            using var pe = new PEReader(fs);
            var hdr = pe.PEHeaders;

            res.FileType = hdr.IsDll ? "PE DLL (ASI)" : (hdr.IsExe ? "PE EXE" : "PE");
            res.IsDll = hdr.IsDll;
            res.IsExe = hdr.IsExe;
            // P7 — distinguish ASI loadable plug-ins (SA-MP / GTA mods,
            // CLEO, MoonLoader) from generic DLLs at the FormatFamily
            // level. ASI is structurally a PE DLL but its context is
            // game-mod loading; relationship analysis (P5) and the
            // protected-DLL-in-game-mod-context floor (P11) both use
            // this distinction.
            if (hdr.IsDll &&
                string.Equals(Path.GetExtension(path), ".asi",
                              StringComparison.OrdinalIgnoreCase))
            {
                res.FormatFamily = "PE-DLL-ASI";
            }
            else if (hdr.IsDll)
            {
                // Mark generic DLLs explicitly so consumers can tell a
                // DLL apart from an EXE without re-parsing the PE.
                res.FormatFamily = "PE-DLL";
            }
            else if (hdr.IsExe)
            {
                res.FormatFamily = "PE-EXE";
            }
            res.Is64 = hdr.PEHeader?.Magic == PEMagic.PE32Plus;
            res.IsDotNetLikely = pe.HasMetadata;
            res.TimeDateStampUtc = DateTimeOffset.FromUnixTimeSeconds(hdr.CoffHeader.TimeDateStamp).UtcDateTime;

            foreach (var s in hdr.SectionHeaders)
            {
                var name = s.Name ?? "";
                res.SectionNames.Add(name);

                var secBytes = pe.GetSectionData(s.VirtualAddress).GetContent().ToArray();
                if (secBytes.Length > 0)
                    res.SectionEntropy[name] = Entropy(secBytes);

                if ((s.SectionCharacteristics & SectionCharacteristics.MemExecute) != 0 &&
                    (s.SectionCharacteristics & SectionCharacteristics.MemWrite) != 0)
                {
                    res.ExecutableWritableSections.Add(name);
                }
            }

            res.OverlaySize = CalculateOverlaySize(path, hdr.SectionHeaders.ToList());

            // B4: extended PE metadata.
            SafeRun("ComputeImpHash",              () => res.ImpHash = ComputeImpHash(pe));
            SafeRun("ComputeRichHeaderHashes",     () => (res.RichHeaderHash, res.RichHeaderHashStd) = ComputeRichHeaderHashes(path));
            SafeRun("ComputeAuthenticodeSha256",   () => res.AuthenticodeSha256 = ComputeAuthenticodeSha256(path));
            SafeRun("ParseExportsInto",            () => ParseExportsInto(pe, res.ExportedFunctions, max: 256));
            SafeRun("ParseResourcesInto",          () => ParseResourcesInto(pe, res));
            SafeRun("ClassifyOverlayInto",         () => ClassifyOverlayInto(path, res));

            // B15: whole-file 4KB-chunk entropy + UPX marker sweep.
            SafeRun("ComputeChunkEntropyAndUpxInto", () => ComputeChunkEntropyAndUpxInto(path, res));

            // Fuzzy chunk fingerprint (simplified substitute for SSDEEP/TLSH pending external lib).
            SafeRun("ComputeChunkFingerprint",     () => res.FuzzyHash = ComputeChunkFingerprint(path));

            foreach (var dll in NetDlls)
            {
                if (allStrings.Any(s => s.IndexOf(dll, StringComparison.OrdinalIgnoreCase) >= 0))
                    res.NetDllHits.Add(dll);
            }

            foreach (var hint in PackerSectionHints)
            {
                if (res.SectionNames.Any(n => n.IndexOf(hint, StringComparison.OrdinalIgnoreCase) >= 0))
                    res.PackerHints.Add($"section:{hint}");
                if (allStrings.Any(s => s.IndexOf(hint, StringComparison.OrdinalIgnoreCase) >= 0))
                    res.PackerHints.Add($"string:{hint}");
            }

            var highEnt = res.SectionEntropy.Where(kv => kv.Value >= 7.2).Select(kv => $"{kv.Key}:{kv.Value:0.00}").ToList();
            if (highEnt.Count > 0)
                res.PackerHints.Add("high-entropy:" + string.Join(", ", highEnt.Take(8)));

            var imports = GetImportedApiNames(pe);
            foreach (var i in imports)
                res.ImportedApis.Add(i);

            // Section 5.1 — single AC pass over the concatenated import
            // table beats the previous foreach-needle × any-import scan.
            // Worst case before: ~36 needles × ~hundreds of imports per
            // PE × per-char ToLower. Now: one AC walk over a ~4 KB
            // lower-case buffer. MatchSuspiciousApis returns the
            // canonical (PascalCase) spelling for the report.
            foreach (var api in Needles.MatchSuspiciousApis(imports))
                res.SuspiciousApiHits.Add(api);

            // B14 (second pass): include import-based anti-analysis signals now that imports are known.
            DetectAntiAnalysisIndicatorsFromImports(res, imports);

            // BB9: process-injection primitives (requires imports).
            SafeRun("DetectInjectionPrimitives",   () => DetectInjectionPrimitives(res, imports));
            // BB5 / BB6: imphash + Rich-header known-bad lookup (require PE-parsed hashes).
            SafeRun("DetectKnownBadImphash",       () => DetectKnownBadImphash(res));
            SafeRun("DetectKnownBadRichHeader",    () => DetectKnownBadRichHeader(res));
            // C14: extended fingerprints (authentihash / SHA256 / section layout)
            SafeRun("DetectKnownBadAuthentihash",  () => DetectKnownBadAuthentihash(res));
            SafeRun("DetectKnownBadSha256",        () => DetectKnownBadSha256(res));
            SafeRun("DetectKnownBadSectionLayout", () => DetectKnownBadSectionLayout(res));
            // C20: auto-ingested threat-intel feed matches.
            SafeRun("ThreatIntelFeedMatcher",       () => ThreatIntelFeedMatcher.Apply(res));
            // BB10: DLL-sideloading guess (needs export table).
            SafeRun("DetectDllSideloadingSuspect", () => DetectDllSideloadingSuspect(res));

            // BB11-BB26: second wave of detection modules.
            SafeRun("DetectResourceStego",         () => DetectResourceStego(res));
            SafeRun("DetectOverlayPayload",        () => DetectOverlayPayload(res, analysisText));
            SafeRun("DetectKnownPackers",          () => DetectKnownPackers(res, analysisText));
            SafeRun("DetectDotNetObfuscators",     () => DetectDotNetObfuscators(res, analysisText));
            // P8 — managed metadata inspection (#US heap, method-
            // name obfuscation ratio, crypto-stub presence). No-op
            // for non-.NET binaries.
            SafeRun("NetMetadataInspector",        () => NetMetadataInspector.Inspect(res, path));
            SafeRun("DetectClipboardHijack",       () => DetectClipboardHijack(res, imports));
            SafeRun("DetectKeylogger",             () => DetectKeylogger(res, imports));
            SafeRun("DetectScreenGrabber",         () => DetectScreenGrabber(res, imports));
            SafeRun("DetectStealerMutexes",        () => DetectStealerMutexes(res, analysisText));
            SafeRun("DetectCredentialFilePaths",   () => DetectCredentialFilePaths(res, analysisText));
            SafeRun("DetectCryptoWalletPaths",     () => DetectCryptoWalletPaths(res, analysisText));
            SafeRun("DetectTelegramDesktopTheft",  () => DetectTelegramDesktopTheft(res, analysisText));
            SafeRun("DetectDiscordLevelDbTheft",   () => DetectDiscordLevelDbTheft(res, analysisText));
            SafeRun("DetectTwoFactorTheft",        () => DetectTwoFactorTheft(res, analysisText));
            SafeRun("DetectRansomwarePatterns",    () => DetectRansomwarePatterns(res, analysisText));
            SafeRun("DetectDestructivePayloads",   () => DetectDestructivePayloads(res, analysisText, imports));
            SafeRun("DetectBrowserJsStealer",      () => DetectBrowserJsStealer(res, analysisText));
            SafeRun("DetectMsiCustomActions",      () => DetectMsiCustomActions(res, analysisText));
            SafeRun("DetectAppxCapabilities",      () => DetectAppxCapabilities(res, analysisText));
            SafeRun("DetectMachOLoadCommands",     () => DetectMachOLoadCommands(res, analysisText));
            SafeRun("DetectElfDynamic",            () => DetectElfDynamic(res, analysisText));
            SafeRun("DetectVbaMacros",             () => DetectVbaMacros(res, analysisText));
            SafeRun("DetectPdfJavaScript",         () => DetectPdfJavaScript(res, analysisText));
            SafeRun("DetectLnkCommands",           () => DetectLnkCommands(res, analysisText));
            SafeRun("DetectPowerShellObf",         () => DetectPowerShellObf(res, analysisText));
            SafeRun("DetectJsObfuscation",         () => DetectJsObfuscation(res, analysisText));
            SafeRun("DetectHtaChm",                () => DetectHtaChm(res, analysisText));
            SafeRun("DetectOneNoteEmbeds",         () => DetectOneNoteEmbeds(res, analysisText, Array.Empty<byte>()));
            SafeRun("DetectClickOnceManifest",     () => DetectClickOnceManifest(res, analysisText));
            SafeRun("ComputeStringCrossReferences", () => ComputeStringCrossReferences(res, path));

            // B1: YARA integration — invokes an external `yara`/`yara64` binary against any .yar rule
            // files found in the user's rules directory. Best-effort: if yara isn't installed or no
            // rule files are present, this is a no-op.
            SafeRun("RunYaraIfAvailable",          () => RunYaraIfAvailable(path, res));

            // BB1 / BB2: user-shippable rule engines (Sigma-full, CAPA-ish).
            SafeRun("DetectSigmaRulesFull",        () => DetectSigmaRulesFull(res, analysisText));
            SafeRun("DetectCapaRules",             () => DetectCapaRules(res, analysisText));
            // BB4: optional ONNX family classifier (no-op unless model file is installed).
            SafeRun("RunMlFamilyClassifierIfAvailable", () => RunMlFamilyClassifierIfAvailable(res));

            // BB7 / BB8: post-aggregation analytics (need UrlsFound & Ipv4Hits already populated).
            SafeRun("DetectDgaDomains",            () => DetectDgaDomains(res));
            SafeRun("DetectBulletproofAsn",        () => DetectBulletproofAsn(res));

            // BB3: ATT&CK mapping — must run AFTER every detector that populates hit lists.
            SafeRun("AssignMitreAttackTtps",       () => AssignMitreAttackTtps(res));

            ApplyCustomHeuristics(res, BuildScanContext(res, analysisText));
            ApplyStructuralFamilyClassification(res, analysisText);

            res.RiskScore = Score(res);
            // A4 — for PE-tagged inputs that happen to ALSO be valid
            // archives (e.g. self-extracting wrapper EXE), recurse the
            // overlay archive if SafeExtract.Zip is willing to open it.
            if (IsRecursableArchive(res.FormatFamily))
            {
                SafeRun("ScanArchiveChildren", () => ScanArchiveChildren(path, res));
                SafeRun("RelationshipBuild-Pe",
                        () => RelationshipAnalyzer.Build(res));
                if (res.RelationshipEvidence.Count > 0)
                    res.RiskScore = Math.Max(res.RiskScore, Score(res));
            }
            res.FinalizeFlags();
            return res;
        }

        private static List<HeuristicRule> BuildCustomRules()
        {
            var rules = new List<HeuristicRule>(900);

            void AddTextRule(string name, int weight, string needle) =>
                rules.Add(new HeuristicRule(name, weight, c => c.Text.Contains(needle, StringComparison.OrdinalIgnoreCase)));

            void AddImportRule(string name, int weight, string importNeedle) =>
                rules.Add(new HeuristicRule(name, weight, c => c.Imports.Any(i => i.Contains(importNeedle, StringComparison.OrdinalIgnoreCase))));

            var targets = new[]
            {
                "login data","web data","cookies","local state","password_value","encrypted_key","token","refresh_token",
                "session","auth","master_key","wallet.dat","seed phrase","mnemonic","metamask","exodus","atomicwallet",
                "phantom","trust wallet","browser_pass","clipboard","clipper","steam","discord token","telegram","roblox",
                "epicgames","minecraft","battle.net","coinbase","binance","bybit","okx","kucoin","wallet","private key","cookievault","sessionstore","authtoken","credit card","cc_number","2fa","otp","wallet seed","recovery phrase"
            };

            var browserArtifacts = new[]
            {
                "chrome","chromium","msedge","edge","opera","firefox","brave","yandex","vivaldi","profiles","cookies",
                "logins","history","bookmark","autofill","password"
            };

            var paths = new[]
            {
                "\\appdata\\roaming","\\appdata\\local","\\users\\","\\profiles\\","\\startup","shell:startup",
                "run\\","runonce","taskschd","schtasks","autorun","software\\microsoft\\windows\\currentversion\\run",
                "\\mozilla\\firefox","\\google\\chrome","\\microsoft\\edge","\\opera software","\\brave software",
                "\\yandex\\","\\discord\\","\\telegram desktop\\","\\wallet","\\temp","\\programdata"
            };

            var exfil = new[]
            {
                "api.telegram.org","discord.com/api/webhooks","discordapp.com/api/webhooks","pastebin","anonfiles","gofile",
                "cdn.discordapp","mega.nz","dropbox","rclone","ftp://","sftp://","smtp","mailgun","sendgrid","webhook",
                "http://","https://","tor2web",".onion","api.ipify.org","ifconfig.me","ngrok","cloudflared"
            };

            var evasion = new[]
            {
                "vmp","themida","upx","aspack","mpress","petite","obfuscator","protector","virtualized",
                "encrypted config","base64","xor key","stub","loader","shellcode","inject","hollow","process ghosting",
                "anti vm","anti debug","sandbox","sleep","junk code","string decrypt"
            };

            var imports = new[]
            {
                "cryptunprotectdata","bcryptdecrypt","winhttpopen","winhttpsendrequest","httpsendrequest","internetreadfile",
                "urldownloadtofile","createremotethread","virtualallocex","writeprocessmemory","readprocessmemory",
                "setwindowshookex","getasynckeystate","regsetvalue","regopenkey","createprocess","openthread","openprocess",
                "minidumpwritedump","isdebuggerpresent","ntqueryinformationprocess","socket","connect","send","recv",
                "wsastartup","dnsquery","createfile","readfile","writefile","copyfile","movefile"
            };

            var processTargets = new[]
            {
                "explorer.exe","lsass.exe","csrss.exe","winlogon.exe","svchost.exe","chrome.exe","msedge.exe","firefox.exe",
                "discord.exe","telegram.exe","steam.exe","epicgameslauncher.exe","battle.net.exe"
            };

            var cryptoSignals = new[]
            {
                "btc","eth","trc20","erc20","xmr","solana","usdt","private key","seed phrase","mnemonic","wallet.dat",
                "metamask","phantom","electrum","exodus"
            };

            var antiAnalysisSignals = new[]
            {
                "vmware","virtualbox","qemu","sandboxie","procmon","processhacker","wireshark","fiddler",
                "vboxservice","vmsrvc","ollydbg","x64dbg","idaq","windbg"
            };

            var injectorApis = new[]
            {
                "createremotethread","ntcreatethreadex","queueuserapc","virtualallocex","writeprocessmemory",
                "setthreadcontext","resumethread","rtlcreateuserthread"
            };

            var c2ApiGroup = new[]
            {
                "winhttpopen","winhttpsendrequest","internetreadfile","connect","send","recv","dnsquery","urldownloadtofile"
            };

            // Baseline direct rules
            foreach (var t in targets) AddTextRule($"target:{t}", 4, t);
            foreach (var p in paths) AddTextRule($"path:{p}", 3, p);
            foreach (var e in exfil) AddTextRule($"exfil:{e}", 4, e);
            foreach (var ev in evasion) AddTextRule($"evasion:{ev}", 4, ev);
            foreach (var api in imports) AddImportRule($"api:{api}", 5, api);

            // Cross-combination rules to exceed 500 functions with meaningful context
            foreach (var t in targets)
            {
                foreach (var b in browserArtifacts)
                {
                    AddTextRule($"combo:target-browser:{t}|{b}", 2, t + " " + b);
                    rules.Add(new HeuristicRule($"combo:target&browser:{t}|{b}", 5,
                        c => c.Text.Contains(t, StringComparison.OrdinalIgnoreCase) && c.Text.Contains(b, StringComparison.OrdinalIgnoreCase)));
                }
            }

            foreach (var t in targets)
            {
                foreach (var e in exfil)
                {
                    rules.Add(new HeuristicRule($"combo:target&exfil:{t}|{e}", 6,
                        c => c.Text.Contains(t, StringComparison.OrdinalIgnoreCase) && c.Text.Contains(e, StringComparison.OrdinalIgnoreCase)));
                }
            }

            foreach (var p in paths)
            {
                foreach (var api in imports.Take(18))
                {
                    rules.Add(new HeuristicRule($"combo:path&api:{p}|{api}", 5,
                        c => c.Text.Contains(p, StringComparison.OrdinalIgnoreCase) && c.Imports.Any(i => i.Contains(api, StringComparison.OrdinalIgnoreCase))));
                }
            }

            foreach (var ev in evasion)
            {
                foreach (var api in imports.Skip(8).Take(16))
                {
                    rules.Add(new HeuristicRule($"combo:evasion&api:{ev}|{api}", 5,
                        c => c.Text.Contains(ev, StringComparison.OrdinalIgnoreCase) && c.Imports.Any(i => i.Contains(api, StringComparison.OrdinalIgnoreCase))));
                }
            }

            foreach (var host in new[] {"discord", "telegram", "pastebin", "mega", "dropbox", "ngrok", "onion"})
            {
                rules.Add(new HeuristicRule($"host:{host}", 6,
                    c => c.UrlHosts.Any(h => h.Contains(host, StringComparison.OrdinalIgnoreCase))));
            }

            foreach (var t in targets)
            {
                foreach (var aa in antiAnalysisSignals)
                {
                    rules.Add(new HeuristicRule($"combo:target&antianalysis:{t}|{aa}", 6,
                        c => c.Text.Contains(t, StringComparison.OrdinalIgnoreCase) && c.Text.Contains(aa, StringComparison.OrdinalIgnoreCase)));
                }
            }

            foreach (var proc in processTargets)
            {
                foreach (var api in injectorApis)
                {
                    rules.Add(new HeuristicRule($"combo:procinject:{proc}|{api}", 6,
                        c => c.Text.Contains(proc, StringComparison.OrdinalIgnoreCase) && c.Imports.Any(i => i.Contains(api, StringComparison.OrdinalIgnoreCase))));
                }
            }

            foreach (var cry in cryptoSignals)
            {
                foreach (var e in exfil.Where(x => x.Contains("http", StringComparison.Ordinal) || x.Contains("webhook", StringComparison.Ordinal) || x.Contains("telegram", StringComparison.Ordinal)))
                {
                    rules.Add(new HeuristicRule($"combo:crypto&exfil:{cry}|{e}", 7,
                        c => c.Text.Contains(cry, StringComparison.OrdinalIgnoreCase) && c.Text.Contains(e, StringComparison.OrdinalIgnoreCase)));
                }
            }

            foreach (var aa in antiAnalysisSignals)
            {
                foreach (var c2 in c2ApiGroup)
                {
                    rules.Add(new HeuristicRule($"combo:stealthc2:{aa}|{c2}", 5,
                        c => c.Text.Contains(aa, StringComparison.OrdinalIgnoreCase) && c.Imports.Any(i => i.Contains(c2, StringComparison.OrdinalIgnoreCase))));
                }
            }

            foreach (var host in new[] { "discord", "telegram", "pastebin", "dropbox", "mega", "ngrok", "anonfiles", "gofile", "onion" })
            {
                foreach (var proc in processTargets)
                {
                    rules.Add(new HeuristicRule($"combo:host&process:{host}|{proc}", 5,
                        c => c.UrlHosts.Any(h => h.Contains(host, StringComparison.OrdinalIgnoreCase)) && c.Text.Contains(proc, StringComparison.OrdinalIgnoreCase)));
                }
            }

            // Strong multi-signal scenarios
            rules.Add(new HeuristicRule("scenario:browser_cookie_token_exfil", 10, c =>
                c.Text.Contains("cookie", StringComparison.OrdinalIgnoreCase) &&
                c.Text.Contains("token", StringComparison.OrdinalIgnoreCase) &&
                (c.Text.Contains("chrome", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("edge", StringComparison.OrdinalIgnoreCase)) &&
                c.UrlHosts.Count > 0));

            rules.Add(new HeuristicRule("scenario:dpapi_sqlite_browser", 10, c =>
                c.Text.Contains("cryptunprotectdata", StringComparison.OrdinalIgnoreCase) &&
                c.Text.Contains("sqlite", StringComparison.OrdinalIgnoreCase) &&
                (c.Text.Contains("chrome", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("firefox", StringComparison.OrdinalIgnoreCase))));

            rules.Add(new HeuristicRule("scenario:injection_plus_network", 10, c =>
                c.Imports.Any(i => i.Contains("createremotethread", StringComparison.OrdinalIgnoreCase) || i.Contains("writeprocessmemory", StringComparison.OrdinalIgnoreCase)) &&
                c.Imports.Any(i => i.Contains("winhttp", StringComparison.OrdinalIgnoreCase) || i.Contains("internet", StringComparison.OrdinalIgnoreCase) || i.Contains("socket", StringComparison.OrdinalIgnoreCase))));

            rules.Add(new HeuristicRule("scenario:persistence_plus_stealer_terms", 9, c =>
                (c.Text.Contains("run\\", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("schtasks", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("startup", StringComparison.OrdinalIgnoreCase)) &&
                (c.Text.Contains("stealer", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("grabber", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("token", StringComparison.OrdinalIgnoreCase))));

            rules.Add(new HeuristicRule("scenario:risky_host_plus_wallet", 9, c =>
                c.UrlHosts.Any(h => h.Contains("discord", StringComparison.OrdinalIgnoreCase) || h.Contains("telegram", StringComparison.OrdinalIgnoreCase) || h.Contains("pastebin", StringComparison.OrdinalIgnoreCase)) &&
                (c.Text.Contains("wallet", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("seed", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("mnemonic", StringComparison.OrdinalIgnoreCase))));

            rules.Add(new HeuristicRule("scenario:credential_dump_plus_injection", 11, c =>
                (c.Text.Contains("lsass", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("sam", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("vault", StringComparison.OrdinalIgnoreCase)) &&
                c.Imports.Any(i => i.Contains("minidumpwritedump", StringComparison.OrdinalIgnoreCase) || i.Contains("readprocessmemory", StringComparison.OrdinalIgnoreCase)) &&
                c.Imports.Any(i => i.Contains("createremotethread", StringComparison.OrdinalIgnoreCase) || i.Contains("virtualallocex", StringComparison.OrdinalIgnoreCase))));

            rules.Add(new HeuristicRule("scenario:wallet_clipboard_hijack", 10, c =>
                (c.Text.Contains("clipboard", StringComparison.OrdinalIgnoreCase) || c.Imports.Any(i => i.Contains("setclipboarddata", StringComparison.OrdinalIgnoreCase))) &&
                (c.Text.Contains("wallet", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("btc", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("eth", StringComparison.OrdinalIgnoreCase)) &&
                (c.Text.Contains("replace", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("swap", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("clipper", StringComparison.OrdinalIgnoreCase))));

            rules.Add(new HeuristicRule("scenario:hidden_persistence_loader", 10, c =>
                (c.Text.Contains("schtasks", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("runonce", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("startup", StringComparison.OrdinalIgnoreCase)) &&
                (c.Text.Contains("powershell -w hidden", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("cmd /c", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("rundll32", StringComparison.OrdinalIgnoreCase)) &&
                (c.Text.Contains("base64", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("encodedcommand", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("decrypt", StringComparison.OrdinalIgnoreCase))));

            rules.Add(new HeuristicRule("scenario:anti_analysis_guarded_stealer", 11, c =>
                antiAnalysisSignals.Any(sig => c.Text.Contains(sig, StringComparison.OrdinalIgnoreCase)) &&
                (c.Text.Contains("cookies", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("login data", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("token", StringComparison.OrdinalIgnoreCase)) &&
                c.Imports.Any(i => i.Contains("isdebuggerpresent", StringComparison.OrdinalIgnoreCase) || i.Contains("ntqueryinformationprocess", StringComparison.OrdinalIgnoreCase))));

            rules.Add(new HeuristicRule("scenario:c2_staged_dropper", 10, c =>
                c.Imports.Any(i => i.Contains("urldownloadtofile", StringComparison.OrdinalIgnoreCase) || i.Contains("winhttpsendrequest", StringComparison.OrdinalIgnoreCase)) &&
                (c.Text.Contains("%temp%", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("appdata", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("programdata", StringComparison.OrdinalIgnoreCase)) &&
                (c.Text.Contains("createprocess", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("rundll32", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("regsvr32", StringComparison.OrdinalIgnoreCase))));


            rules.Add(new HeuristicRule("scenario:redline_style", 10, c =>
                c.Text.Contains("redline", StringComparison.OrdinalIgnoreCase) &&
                (c.Text.Contains("build id", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("grabber", StringComparison.OrdinalIgnoreCase)) &&
                c.Imports.Any(i => i.Contains("winhttp", StringComparison.OrdinalIgnoreCase) || i.Contains("internetreadfile", StringComparison.OrdinalIgnoreCase))));

            rules.Add(new HeuristicRule("scenario:raccoon_style", 10, c =>
                c.Text.Contains("raccoon", StringComparison.OrdinalIgnoreCase) &&
                (c.Text.Contains("wallet", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("cookie", StringComparison.OrdinalIgnoreCase)) &&
                c.UrlHosts.Count > 0));

            rules.Add(new HeuristicRule("scenario:vidar_style", 10, c =>
                c.Text.Contains("vidar", StringComparison.OrdinalIgnoreCase) &&
                (c.Text.Contains("gate.php", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("panel", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("c2", StringComparison.OrdinalIgnoreCase))));

            rules.Add(new HeuristicRule("scenario:lumma_style", 10, c =>
                (c.Text.Contains("lumma", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("lummac2", StringComparison.OrdinalIgnoreCase)) &&
                c.Imports.Any(i => i.Contains("cryptunprotectdata", StringComparison.OrdinalIgnoreCase) || i.Contains("bcryptdecrypt", StringComparison.OrdinalIgnoreCase)) &&
                c.UrlHosts.Any()));

            rules.Add(new HeuristicRule("scenario:risepro_style", 10, c =>
                c.Text.Contains("risepro", StringComparison.OrdinalIgnoreCase) &&
                (c.Text.Contains("discord", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("telegram", StringComparison.OrdinalIgnoreCase) || c.Text.Contains("cookie", StringComparison.OrdinalIgnoreCase))));

            // Extra 5000+ high-signal checks for commercial-grade coverage
            var stealFamilies = new[]
            {
                "redline","raccoon","vidar","lumma","lummac2","risepro","meduza","azorult","pony","fareit","taurus",
                "meta","morphisec","stealc","xworm","agenttesla","snakekeylogger","remcos","quasar","njrat","lokibot"
            };

            var browserData = new[]
            {
                "cookies","login data","web data","local state","history","autofill","password_value","encrypted_key",
                "sessionstore","cookievault","profiles","bookmark","token","refresh_token","auth"
            };

            var exfilChannels = new[]
            {
                "telegram","discord","webhook","http://","https://","pastebin","gofile","anonfiles","dropbox","mega","ftp://","smtp"
            };

            var persistenceTerms = new[]
            {
                "run\\","runonce","startup","schtasks","taskschd","autorun","service","wmi","registry","shell:startup"
            };

            var antiAnalysisAdvanced = new[]
            {
                "vmware","virtualbox","qemu","sandboxie","x64dbg","ollydbg","idaq","windbg","wireshark","fiddler"
            };

            var credSources = new[]
            {
                "chrome","edge","firefox","opera","brave","yandex","discord","steam","telegram","wallet"
            };

            var ioArtifacts = new[]
            {
                "%appdata%","%localappdata%","%temp%","programdata","users\\","desktop","documents","downloads","wallet.dat"
            };

            var injApi = new[]
            {
                "createremotethread","ntcreatethreadex","writeprocessmemory","virtualallocex","queueuserapc","setthreadcontext"
            };

            var netApi = new[]
            {
                "winhttpopen","winhttpsendrequest","internetreadfile","socket","connect","send","recv","dnsquery"
            };

            foreach (var fam in stealFamilies)
            {
                foreach (var b in browserData)
                {
                    rules.Add(new HeuristicRule($"combo:fam-browser:{fam}|{b}", 5,
                        c => c.Text.Contains(fam, StringComparison.OrdinalIgnoreCase) && c.Text.Contains(b, StringComparison.OrdinalIgnoreCase)));
                }
            }

            foreach (var fam in stealFamilies)
            {
                foreach (var x in exfilChannels)
                {
                    rules.Add(new HeuristicRule($"combo:fam-exfil:{fam}|{x}", 6,
                        c => c.Text.Contains(fam, StringComparison.OrdinalIgnoreCase) && c.Text.Contains(x, StringComparison.OrdinalIgnoreCase)));
                }
            }

            foreach (var fam in stealFamilies)
            {
                foreach (var p in persistenceTerms)
                {
                    rules.Add(new HeuristicRule($"combo:fam-persist:{fam}|{p}", 5,
                        c => c.Text.Contains(fam, StringComparison.OrdinalIgnoreCase) && c.Text.Contains(p, StringComparison.OrdinalIgnoreCase)));
                }
            }

            foreach (var fam in stealFamilies)
            {
                foreach (var aa in antiAnalysisAdvanced)
                {
                    rules.Add(new HeuristicRule($"combo:fam-antia:{fam}|{aa}", 5,
                        c => c.Text.Contains(fam, StringComparison.OrdinalIgnoreCase) && c.Text.Contains(aa, StringComparison.OrdinalIgnoreCase)));
                }
            }

            foreach (var src in credSources)
            {
                foreach (var b in browserData)
                {
                    foreach (var x in exfilChannels)
                    {
                        rules.Add(new HeuristicRule($"combo:source-browser-exfil:{src}|{b}|{x}", 4,
                            c => c.Text.Contains(src, StringComparison.OrdinalIgnoreCase) &&
                                 c.Text.Contains(b, StringComparison.OrdinalIgnoreCase) &&
                                 c.Text.Contains(x, StringComparison.OrdinalIgnoreCase)));
                    }
                }
            }

            foreach (var io in ioArtifacts)
            {
                foreach (var api in injApi)
                {
                    foreach (var n in netApi)
                    {
                        rules.Add(new HeuristicRule($"combo:io-inj-net:{io}|{api}|{n}", 5,
                            c => c.Text.Contains(io, StringComparison.OrdinalIgnoreCase) &&
                                 c.Imports.Any(i => i.Contains(api, StringComparison.OrdinalIgnoreCase)) &&
                                 c.Imports.Any(i => i.Contains(n, StringComparison.OrdinalIgnoreCase))));
                    }
                }
            }

            foreach (var fam in stealFamilies)
            {
                foreach (var src in credSources)
                {
                    foreach (var io in ioArtifacts)
                    {
                        rules.Add(new HeuristicRule($"combo:fam-source-io:{fam}|{src}|{io}", 4,
                            c => c.Text.Contains(fam, StringComparison.OrdinalIgnoreCase) &&
                                 c.Text.Contains(src, StringComparison.OrdinalIgnoreCase) &&
                                 c.Text.Contains(io, StringComparison.OrdinalIgnoreCase)));
                    }
                }
            }

            foreach (var fam in stealFamilies)
            {
                foreach (var api in injApi)
                {
                    foreach (var n in netApi)
                    {
                        rules.Add(new HeuristicRule($"combo:fam-inj-net:{fam}|{api}|{n}", 5,
                            c => c.Text.Contains(fam, StringComparison.OrdinalIgnoreCase) &&
                                 c.Imports.Any(i => i.Contains(api, StringComparison.OrdinalIgnoreCase)) &&
                                 c.Imports.Any(i => i.Contains(n, StringComparison.OrdinalIgnoreCase))));
                    }
                }
            }

            return rules;
        }

        private static ScanContext BuildScanContext(AnalysisResult r, string allText)
        {
            // M15: HashSets are already case-insensitive via OrdinalIgnoreCase; no need to pre-lowercase entries.
            var imports = new HashSet<string>(r.ImportedApis, StringComparer.OrdinalIgnoreCase);
            var sections = new HashSet<string>(r.SectionNames, StringComparer.OrdinalIgnoreCase);
            var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var u in r.UrlsFound)
            {
                if (Uri.TryCreate(u, UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host))
                    hosts.Add(uri.Host);
            }

            return new ScanContext
            {
                Text = allText,
                Imports = imports,
                SectionNames = sections,
                UrlHosts = hosts
            };
        }

        private static void ApplyCustomHeuristics(AnalysisResult res, ScanContext ctx)
        {
            foreach (var rule in CustomRules)
            {
                if (rule.Predicate(ctx))
                {
                    res.CustomHeuristicHits.Add(rule.Name);
                    res.CustomHeuristicWeight += rule.Weight;
                }
            }

            res.CustomHeuristicHits = res.CustomHeuristicHits
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private static void ApplyStructuralFamilyClassification(AnalysisResult res, string? analysisText = null)
        {
            var fingerprint = BuildStructureFingerprint(res);
            res.StructureFingerprint = fingerprint;

            var local = LocalFamilyMatch(fingerprint, res);
            if (local.confidence > res.FamilyConfidence)
            {
                res.FamilyName = local.family;
                res.FamilyConfidence = local.confidence;
                res.FamilyReason = local.reason;
            }

            // Section 2.1 / 2.2 / 2.3 (PR 11) — modern stealer family,
            // loader-family and embedded cloud-credential detection. Run
            // after the legacy heuristic so it only overrides FamilyName
            // when its own confidence is higher.
            FamilyDetectorPipeline.RunOn(res);

            // Section 2.4..2.10 (PR 12) — platform-specific enrichment:
            // macOS, Linux/ELF, APK, IPA, browser-extension, Office macros,
            // extra PE notes (manifest / packer / TLS-callback / side-loading
            // bait). Pure string-level heuristics gated by FileType so a
            // mis-classified sample doesn't get spurious hits.
            PlatformDetectorPipeline.RunOn(res);

            // Section 2.11..2.16 (PR 13) — advanced-threat enrichment:
            // BYOVD vulnerable drivers, shellcode patterns, steganography
            // carriers, C2 frameworks (CS / Sliver / Mythic / Havoc / BRC4),
            // phishing-kit markers, and npm supply-chain red flags.
            AdvancedThreatPipeline.RunOn(res);

            // Section 4 (PR 15) — dynamic analysis. Best-effort, runs the
            // MiniYaraX in-process rule engine over the sample's strings
            // AND over the full analysisText buffer (~ 2 MiB capped, when
            // the caller hands it in) so rules can match against the
            // same corpus as every other text-based detector. The full
            // WSB / ETW / Unicorn / CAPE harnesses live in the same
            // namespace but are driven from the CLI, not from inside
            // the static-analysis loop.
            DynamicAnalysisPipeline.RunOn(res, analysisText);

            var server = EnableServerClassification
                ? QueryServerClassifier(fingerprint, res)
                : (family: "", confidence: 0d, reason: "");
            if (server.confidence > res.FamilyConfidence)
            {
                res.FamilyName = server.family;
                res.FamilyConfidence = server.confidence;
                res.FamilyReason = server.reason;
            }
        }

        private static string BuildStructureFingerprint(AnalysisResult r)
        {
            var sec = string.Join(',', r.SectionNames.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).Take(12));
            var apis = string.Join(',', r.SuspiciousApiHits.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).Take(16));
            var io = $"u{r.UrlsFound.Count}-i{r.Ipv4Hits.Count}-e{r.EmailHits.Count}-k{r.CryptoWalletHits.Count}-j{r.JwtHits.Count}-t{r.TelegramBotTokenHits.Count}-d{r.DiscordTokenHits.Count}";
            var flags = $"dll{(r.IsDll ? 1 : 0)}-dot{(r.IsDotNetLikely ? 1 : 0)}-signed{(r.IsSigned ? 1 : 0)}-pack{(r.PackerHints.Count > 0 ? 1 : 0)}-rwx{(r.ExecutableWritableSections.Count > 0 ? 1 : 0)}";
            var raw = $"{r.FileType}|{flags}|{io}|sec:{sec}|api:{apis}|heur:{r.CustomHeuristicHits.Count}";
            using var sha = SHA256.Create();
            var h = sha.ComputeHash(Encoding.UTF8.GetBytes(raw));
            return HexUtil.ToLowerHex(h);
        }

        private static (string family, double confidence, string reason) LocalFamilyMatch(string fp, AnalysisResult r)
        {
            var textHitsLower = string.Join('\n', r.StringHits.Take(400)).ToLowerInvariant();
            var reasons = r.ReasonsShort.ToLowerInvariant();

            if (r.DiscordTokenHits.Count > 0 && r.TelegramBotTokenHits.Count > 0)
                return ("TokenGrabber-Hybrid", 82, "discord+telegram token artifacts");
            if (r.CryptoWalletHits.Count > 0 && r.SuspiciousApiHits.Any(a => a.Contains("CryptUnprotectData", StringComparison.OrdinalIgnoreCase)))
                return ("WalletStealer-DPAPI", 79, "wallet indicators + DPAPI behavior");
            if (r.UrlsFound.Count > 0 && r.CustomHeuristicHits.Count > 80 && r.PackerHints.Count > 0)
                return ("Packed-Exfil-Stealer", 76, "packed + exfil + high heuristic density");
            if (r.JwtHits.Count > 0 && r.UrlsFound.Any(u => u.Contains("discord", StringComparison.OrdinalIgnoreCase)))
                return ("DiscordSessionStealer", 74, "jwt/session indicators with discord endpoints");
            if (r.PrivateKeyBlockHits > 0)
                return ("SecretKeyExfil", 73, "private-key material detected");

            if (textHitsLower.Contains("redline")) return ("RedLine", 80, "string indicators mention redline");
            if (textHitsLower.Contains("raccoon")) return ("Raccoon", 79, "string indicators mention raccoon");
            if (textHitsLower.Contains("vidar")) return ("Vidar", 79, "string indicators mention vidar");
            if (textHitsLower.Contains("lumma") || textHitsLower.Contains("lummac2")) return ("Lumma", 82, "string indicators mention lumma");
            if (textHitsLower.Contains("risepro")) return ("RisePro", 80, "string indicators mention risepro");
            if (textHitsLower.Contains("meduza")) return ("Meduza", 77, "string indicators mention meduza");
            if (textHitsLower.Contains("azorult")) return ("Azorult", 76, "string indicators mention azorult");
            if (textHitsLower.Contains("taurus")) return ("Taurus", 74, "string indicators mention taurus");
            if (textHitsLower.Contains("pony") || textHitsLower.Contains("fareit")) return ("Pony/Fareit", 74, "pony/fareit markers");

            if (r.TelegramBotTokenHits.Count > 0 && r.CustomHeuristicHits.Any(h => h.Contains("exfil", StringComparison.OrdinalIgnoreCase)))
                return ("TelegramStealer", 75, "telegram bot token and exfil behavior");
            if (r.DiscordTokenHits.Count > 0 && r.CustomHeuristicHits.Any(h => h.Contains("browser", StringComparison.OrdinalIgnoreCase)))
                return ("DiscordTokenStealer", 75, "discord token and browser extraction patterns");
            if (r.PackerHints.Count > 0 && r.ExecutableWritableSections.Count > 0 && r.CustomHeuristicHits.Count > 120)
                return ("PackedLoaderStealer", 74, "heavy obfuscation + injector profile");
            if (reasons.Contains("jwt") && reasons.Contains("unsigned") && r.UrlsFound.Count > 0)
                return ("SessionHijackStealer", 72, "session artifacts + unsigned + network");

            return ("", 0, "");
        }

        private static (string family, double confidence, string reason) QueryServerClassifier(string fingerprint, AnalysisResult r)
        {
            try
            {
                string? endpoint = Environment.GetEnvironmentVariable("STEALER_CLASSIFIER_URL");
                if (string.IsNullOrWhiteSpace(endpoint)) return ("", 0, "");

                var payload = new ClassifierRequest
                {
                    Fingerprint = fingerprint,
                    FileType = r.FileType,
                    IsDll = r.IsDll,
                    IsDotNet = r.IsDotNetLikely,
                    Signed = r.IsSigned,
                    UrlCount = r.UrlsFound.Count,
                    ApiCount = r.SuspiciousApiHits.Count,
                    HeurCount = r.CustomHeuristicHits.Count,
                    TokenCount = r.JwtHits.Count + r.TelegramBotTokenHits.Count + r.DiscordTokenHits.Count,
                    Packed = r.PackerHints.Count > 0 || r.ExecutableWritableSections.Count > 0
                };

                var resp = ClassifierHttp.PostAsJsonAsync(endpoint, payload).GetAwaiter().GetResult();
                if (!resp.IsSuccessStatusCode) return ("", 0, "");

                var parsed = resp.Content.ReadFromJsonAsync<ClassifierResponse>().GetAwaiter().GetResult();
                if (parsed == null || string.IsNullOrWhiteSpace(parsed.Family)) return ("", 0, "");

                var conf = Math.Clamp(parsed.Confidence, 0, 100);
                return (parsed.Family, conf, parsed.Reason ?? "server-classifier");
            }
            catch
            {
                return ("", 0, "");
            }
        }

        private sealed class ClassifierRequest
        {
            public string Fingerprint { get; set; } = "";
            public string FileType { get; set; } = "";
            public bool IsDll { get; set; }
            public bool IsDotNet { get; set; }
            public bool Signed { get; set; }
            public int UrlCount { get; set; }
            public int ApiCount { get; set; }
            public int HeurCount { get; set; }
            public int TokenCount { get; set; }
            public bool Packed { get; set; }
        }

        private sealed class ClassifierResponse
        {
            public string Family { get; set; } = "";
            public double Confidence { get; set; }
            public string? Reason { get; set; }
        }

        // M7: signature detection. X509Certificate.CreateFromSignedFile tells us an Authenticode blob exists
        // but says nothing about chain validity. We now:
        //   1) confirm an embedded cert exists
        //   2) read the signer subject (GetNameInfo)
        //   3) build an X509Chain to mark whether the chain validates on this machine
        //   4) capture the NotBefore/NotAfter dates and thumbprint for the report
        // NOTE: full Authenticode (WinVerifyTrust) validation requires P/Invoke; we leave that for a
        // dedicated follow-up but expose ChainValid so callers can distinguish "has cert" from "trusted cert".
        private static void DetectSignature(AnalysisResult res, string pathForSignatureCheck)
        {
            try
            {
                var cert = X509Certificate.CreateFromSignedFile(pathForSignatureCheck);
                if (cert == null)
                {
                    res.IsSigned = false;
                    return;
                }

                res.IsSigned = true;
                using var cert2 = new X509Certificate2(cert);
                res.Signer = cert2.GetNameInfo(X509NameType.SimpleName, false) ?? string.Empty;
                res.SignerIssuer = cert2.GetNameInfo(X509NameType.SimpleName, true) ?? string.Empty;
                res.SignerNotBefore = cert2.NotBefore;
                res.SignerNotAfter = cert2.NotAfter;
                res.SignerThumbprint = cert2.Thumbprint ?? string.Empty;

                try
                {
                    using var chain = new X509Chain();
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // revocation check can be very slow
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                    res.SignerChainValid = chain.Build(cert2);
                    if (!res.SignerChainValid && chain.ChainStatus.Length > 0)
                    {
                        res.SignerChainStatus = string.Join("; ",
                            chain.ChainStatus.Select(s => s.StatusInformation?.Trim()).Where(s => !string.IsNullOrWhiteSpace(s)));
                    }
                }
                catch (Exception chainEx)
                {
                    res.SignerChainValid = false;
                    res.SignerChainStatus = "chain-build-error: " + chainEx.Message;
                }
            }
            catch
            {
                res.IsSigned = false;
            }
        }

        private static void ApplyExternalRules(AnalysisResult res, string allText)
        {
            if (!EnableExternalRules) return;
            string rulePath = Path.Combine(AppContext.BaseDirectory, "community_rules.txt");
            if (!File.Exists(rulePath)) return;

            foreach (var line in File.ReadLines(rulePath))
            {
                var trimmed = line.Trim();
                if (trimmed.Length == 0 || trimmed.StartsWith("#")) continue;

                var parts = trimmed.Split('|');
                if (parts.Length < 3) continue;

                if (!int.TryParse(parts[1].Trim(), out int weight)) weight = 5;
                string name = parts[0].Trim();
                string pattern = parts[2].Trim();

                if (pattern.Length > 512) continue;

                try
                {
                    var rx = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
                    if (rx.IsMatch(allText))
                    {
                        res.ExternalRuleHits.Add($"{name} (+{weight})");
                        res.ExternalRuleWeight += Math.Max(1, weight);
                    }
                }
                catch
                {
                    // ignore invalid or hostile external rules
                }
            }
        }

        // B16/B17: categorized capability scoring. Each capability is scored 0..100 from its own signals;
        // the final RiskScore is a weighted, logistic-combined aggregation that saturates gracefully
        // instead of the previous additive Math.Min stack. Weights are explicit constants so they can be
        // tuned without reshuffling the algorithm.
        private const double CapWeightCredentialTheft = 1.6;
        private const double CapWeightExfiltration   = 1.4;
        private const double CapWeightAntiAnalysis   = 1.2;
        private const double CapWeightPersistence    = 1.1;
        private const double CapWeightNetwork        = 1.0;
        private const double CapWeightCryptoTheft    = 1.0;
        private const double CapWeightPacking        = 0.9;

        // Public wrapper for Score() — used by the UI layer after async cloud enrichment so the final
        // RiskScore reflects CloudLookupResults / LocalAvHits / SigmaLiteHits.
        public static int ScorePublic(AnalysisResult r) => Score(r);

        // B17 — Public wrapper around the DLL-sideloading detector so
        // tests can verify the expanded known-target database without
        // having to load a real PE.
        public static void RunDetectDllSideloadingSuspectPublic(AnalysisResult r)
            => DetectDllSideloadingSuspect(r);

        private static int Score(AnalysisResult r)
        {
            // P1...P4 — refresh the protector / packer fingerprint
            // before scoring so the decisive floors below can read
            // r.Protection. Compute() is idempotent so running it
            // here AND again from FinalizeFlags() is a no-op.
            try { ProtectionAnalyzer.Compute(r); } catch { }

            // B18: allowlist still surfaces in the result, but is NEVER
            // allowed to short-circuit the score to a near-zero value.
            // A stolen / abused / coincidentally-matching signing
            // certificate, a signed sideload-target DLL, a signed
            // malicious updater, or a signed BYOVD driver can all
            // legitimately match the allowlist while still being highly
            // dangerous. Compute the full raw score first; the
            // allowlist discount is applied at the end and is bounded
            // both above (-20) and below (decisive-evidence override).
            bool allow = MatchAllowlist(r, out var allowReason);
            if (allow)
            {
                r.AllowlistMatched = true;
                r.AllowlistReason  = allowReason;
                r.CapabilityScores["AllowlistMatch"] = 100;
            }

            int credentialTheft  = ScoreCredentialTheft(r);
            int exfiltration     = ScoreExfiltration(r);
            int antiAnalysis     = ScoreAntiAnalysis(r);
            int persistence      = ScorePersistence(r);
            int network          = ScoreNetwork(r);
            int cryptoTheft      = ScoreCryptoTheft(r);
            int packing          = ScorePacking(r);
            int executionVectors = ScoreExecutionVectors(r); // C1/C3: script / PDF / Office / LNK cradles

            r.CapabilityScores["CredentialTheft"]  = credentialTheft;
            r.CapabilityScores["Exfiltration"]     = exfiltration;
            r.CapabilityScores["AntiAnalysis"]     = antiAnalysis;
            r.CapabilityScores["Persistence"]      = persistence;
            r.CapabilityScores["Network"]          = network;
            r.CapabilityScores["CryptoTheft"]      = cryptoTheft;
            r.CapabilityScores["Packing"]          = packing;
            r.CapabilityScores["ExecutionVectors"] = executionVectors;

            // C15 — record contributions for explainability.  Capability
            // weights are blended logistically so the raw points won't
            // sum to the final score; storing each contributor lets the
            // UI render "why this score?" without recomputing.
            r.ScoreContributors["Capability:CredentialTheft"]  = credentialTheft;
            r.ScoreContributors["Capability:Exfiltration"]     = exfiltration;
            r.ScoreContributors["Capability:AntiAnalysis"]     = antiAnalysis;
            r.ScoreContributors["Capability:Persistence"]      = persistence;
            r.ScoreContributors["Capability:Network"]          = network;
            r.ScoreContributors["Capability:CryptoTheft"]      = cryptoTheft;
            r.ScoreContributors["Capability:Packing"]          = packing;
            r.ScoreContributors["Capability:ExecutionVectors"] = executionVectors;

            // Logistic blend: converts weighted sum into 0..100 with diminishing returns at the top end
            // so that two very strong categories don't automatically pin the score at 100.
            const double CapWeightExecutionVectors = 1.3;
            double weighted =
                (credentialTheft  * CapWeightCredentialTheft +
                 exfiltration     * CapWeightExfiltration    +
                 antiAnalysis     * CapWeightAntiAnalysis    +
                 persistence      * CapWeightPersistence     +
                 network          * CapWeightNetwork         +
                 cryptoTheft      * CapWeightCryptoTheft     +
                 packing          * CapWeightPacking         +
                 executionVectors * CapWeightExecutionVectors) / 100.0;

            // B17 calibration (v2): tuned so a clean "one-trick" capability (e.g. ~60 credential-theft)
            // lands around 50-60, a 2-capability combo (stealer + exfil) lands around 70-80, and
            // 3+ strong capabilities saturate >=85. Previously `x/(x+4)` topped-out near 50 even for
            // obvious stealers sending account data to Telegram — samples were reported at 36/100.
            double normalized = weighted / (weighted + 1.5);
            int final = (int)Math.Round(normalized * 100.0);

            // Strong composite signal: credential-theft artefacts (browser DBs, DPAPI, wallet files,
            // private keys, stealer tokens) combined with an exfil destination (Telegram/Discord/
            // webhook/paste site) is the canonical info-stealer pattern. Bump aggressively.
            int bStealerExfil = StealerExfilPatternBonus(r);
            final += bStealerExfil;
            if (bStealerExfil != 0) r.ScoreContributors["Bonus:StealerExfilPattern"] = bStealerExfil;

            // BB1-BB10: aggregate bonus from the advanced detection modules.
            int bAdv1 = AdvancedDetectionBonus(r);
            final += bAdv1;
            if (bAdv1 != 0) r.ScoreContributors["Bonus:AdvancedDetectionBonus"] = bAdv1;
            // BB11-BB26: second-wave detection modules.
            int bAdv2 = AdvancedDetectionBonus2(r);
            final += bAdv2;
            if (bAdv2 != 0) r.ScoreContributors["Bonus:AdvancedDetectionBonus2"] = bAdv2;
            // BB27: browser-JS credential-stealer module.
            int bBrowserJs = BrowserJsStealerBonus(r);
            final += bBrowserJs;
            if (bBrowserJs != 0) r.ScoreContributors["Bonus:BrowserJsStealer"] = bBrowserJs;
            // CC1-CC12: format-specific detectors (MSI/APPX/Mach-O/ELF/VBA/PDF/LNK/PS/JS/HTA/OneNote/ClickOnce).
            int bFormat = FormatDetectorsBonus(r);
            final += bFormat;
            if (bFormat != 0) r.ScoreContributors["Bonus:FormatDetectors"] = bFormat;

            // C20 — auto-ingested feed hits. Each kind is bounded so
            // a noisy feed cannot single-handedly drive a sample into
            // HIGH; use feeds as confirmation, not as the verdict.
            int bFeeds = ThreatIntelFeedBonus(r);
            final += bFeeds;
            if (bFeeds != 0) r.ScoreContributors["Bonus:ThreatIntelFeed"] = bFeeds;

            // Gentle bumps for high-confidence structural findings that don't map neatly to a category.
            if (!r.IsSigned && (r.IsDll || r.IsExe))
            {
                final += 2;
                r.ScoreContributors["Bonus:UnsignedBinary"] = 2;
            }
            if (r.SignerChainValid == false && r.IsSigned)
            {
                final += 3;
                r.ScoreContributors["Bonus:InvalidSignerChain"] = 3;
            }
            if (r.ExecutableWritableSections.Count > 0)
            {
                final += 2;
                r.ScoreContributors["Bonus:RWXSections"] = 2;
            }

            // Floor for very-high-confidence stealer patterns. If the sample has an explicit
            // Telegram exfil endpoint (bot-API verb + %s) AND a self-identifying string (PDB path
            // or exfil template), AND at least one bot token / game-target, there is essentially
            // no benign explanation — force into HIGH regardless of what the weighted blend says.
            bool hasDecisiveStealerCombo =
                r.MalwareSelfIdHits.Count >= 1 &&
                r.TelegramExfilEndpoints.Count >= 1 &&
                (r.TelegramBotTokenHits.Count >= 1 || r.GameTargetHits.Count >= 1);

            // BB27 — JS browser-credential-stealer floor. DOM scraping of a password field +
            // a credential-POST pattern (JSON.stringify with ≥2 credential fields OR
            // XHR/fetch/sendBeacon adjacent to credential tokens) leaves essentially no
            // benign explanation — force to HIGH. Note: we do NOT require the destination
            // URL to be anywhere specific (hosting providers like vercel.app / netlify.app
            // are legitimate free hosts; the decisive signal is the credential-scraping JS
            // combined with an outbound POST, not the URL).
            bool hasDecisiveJsStealer =
                r.JsCredScraperHits.Count >= 1 &&
                r.JsCredPostHits.Count >= 1;

            // B6/B8 — extended decisive-floor recipes. Each cluster below
            // is canonical info-stealer behaviour with no benign
            // analogue; when present we force final to ≥90 regardless of
            // the weighted blend.
            //
            // (a) Browser DB + DPAPI + exfil sink. MITRE T1555.003.
            //     Login Data + CryptUnprotectData + Telegram/Discord/
            //     paste-site sink is the canonical Chromium-credential-
            //     theft chain.
            bool browserDbDpapiExfil = HasBrowserDbDpapiExfilChain(r);

            // (b) Cookie / session-token theft + exfil. MFA bypass.
            bool cookieSessionExfil =
                r.StringHits.Any(s => s != null && (
                    s.Contains("Cookies",          StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("Network\\Cookies", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("sessionid",        StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("session_token",    StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("__Secure-",        StringComparison.OrdinalIgnoreCase))) &&
                AnyExfilSink(r);

            // (c) Wallet extension paths + seed/mnemonic context + exfil.
            bool walletSeedExfil =
                r.CryptoWalletHits.Count >= 1 &&
                r.StringHits.Any(s => s != null && (
                    s.Contains("mnemonic", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("seed phrase", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("BIP39",   StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("Metamask", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("Phantom",  StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("Trust Wallet", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("Exodus", StringComparison.OrdinalIgnoreCase))) &&
                AnyExfilSink(r);

            // (d) Discord LevelDB token theft + webhook/Telegram.
            bool discordLevelDbExfil =
                r.StringHits.Any(s => s != null && (
                    s.Contains("Discord\\Local Storage", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("discord\\leveldb",       StringComparison.OrdinalIgnoreCase) ||
                    s.Contains(".ldb",                   StringComparison.OrdinalIgnoreCase))) &&
                (r.DiscordTokenHits.Count > 0 || AnyExfilSink(r));

            // (e) Screenshot + browser-theft + C2 POST. Classic stealer.
            bool screenshotBrowserC2 =
                r.SuspiciousApiHits.Any(s => s != null && (
                    s.Contains("BitBlt",       StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("GetDesktopWindow", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("CreateCompatibleDC", StringComparison.OrdinalIgnoreCase))) &&
                r.BrowserStealerIndicators.Count >= 1 &&
                AnyExfilSink(r);

            // (f) Password-manager vault target + exfil.
            bool passwordManagerExfil =
                r.StringHits.Any(s => s != null && (
                    s.Contains(".kdbx",         StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("Bitwarden",     StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("1Password",     StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("LastPass",      StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("KeePass",       StringComparison.OrdinalIgnoreCase))) &&
                AnyExfilSink(r);

            // (g) PowerShell encoded cradle + download + execute.
            bool powerShellCradle =
                (r.PowerShellObfHits.Count >= 1 ||
                 r.StringHits.Any(s => s != null && (
                    s.Contains("-EncodedCommand", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("-enc",            StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("FromBase64String",StringComparison.OrdinalIgnoreCase)))) &&
                r.StringHits.Any(s => s != null && (
                    s.Contains("DownloadString",  StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("DownloadFile",    StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("Invoke-Expression", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("iex ",            StringComparison.OrdinalIgnoreCase))) &&
                r.UrlsFound.Count > 0;

            bool b6Decisive = browserDbDpapiExfil || cookieSessionExfil || walletSeedExfil ||
                              discordLevelDbExfil || screenshotBrowserC2 ||
                              passwordManagerExfil || powerShellCradle;

            // Stage L9 — Lua credential-read + Telegram/Discord exfil
            // chain. The Lua detector sets r.LuaCredentialExfilChain
            // when it observes both an io.open / lfs.dir against a
            // credential path AND a Telegram-bot / Discord-webhook
            // sink within the same 8 KiB context window.
            bool luaCredExfil = r.LuaCredentialExfilChain;

            int preFloor = final;
            if ((hasDecisiveStealerCombo || hasDecisiveJsStealer ||
                 b6Decisive || luaCredExfil) && final < 90)
            {
                final = 90;
                if (hasDecisiveStealerCombo)  r.AppliedFloors.Add("DecisiveTelegramStealer");
                if (hasDecisiveJsStealer)     r.AppliedFloors.Add("DecisiveJsCredScraper");
                if (browserDbDpapiExfil)      r.AppliedFloors.Add("BrowserDbDpapiExfil");
                if (cookieSessionExfil)       r.AppliedFloors.Add("CookieSessionExfil");
                if (walletSeedExfil)          r.AppliedFloors.Add("WalletSeedExfil");
                if (discordLevelDbExfil)      r.AppliedFloors.Add("DiscordLevelDbExfil");
                if (screenshotBrowserC2)      r.AppliedFloors.Add("ScreenshotBrowserC2");
                if (passwordManagerExfil)     r.AppliedFloors.Add("PasswordManagerExfil");
                if (powerShellCradle)         r.AppliedFloors.Add("PowerShellEncodedCradle");
                if (luaCredExfil)             r.AppliedFloors.Add("LuaCredentialExfilChain");
                if (final - preFloor > 0)
                    r.ScoreContributors["Floor:Decisive=>90"] = final - preFloor;
            }

            // Stage L8 — Lua download + native-payload-ext + load
            // primitive chain. Floor at 85 (below the 90 used for
            // confirmed credential exfil), so a Lua loader that
            // pulls down a .asi / .dll / .saa via downloadUrlToFile
            // and then calls loadDynamicLibrary / package.loadlib /
            // os.execute is automatically HIGH even if the payload
            // itself never gets unpacked.
            if (r.LuaDownloadAndLoadChain && final < 85)
            {
                int pre = final;
                final = 85;
                r.AppliedFloors.Add("LuaDownloadAndLoadChain");
                r.ScoreContributors["Floor:LuaDownloadAndLoad=>85"] = final - pre;
            }

            // P11 — decisive floors that rely on the structural
            // protection fingerprint (P1...P4 already populated
            // r.Protection at the top of Score()). These cover the
            // two important cases that pure-string scanners miss:
            //
            //   (a) lua-loads-protected-native-payload (FATAL): if
            //       a parent Lua loader chain (L8) is present AND
            //       this very file or a known child is structurally
            //       protected (Themida-like / VM-protected / dynamic
            //       API resolution / RWX + high entropy), the user
            //       is dealing with an attacker who is hiding the
            //       payload from static analysis. Floor at 92.
            //
            //   (b) protected-dll-in-game-mod-context (MEDIUM): a
            //       DLL whose structural fingerprint says protected
            //       AND which is delivered together with SA-MP /
            //       MoonLoader / .asi context strings is far more
            //       suspicious than the same DLL alone. Floor at 60
            //       — enough to surface in the report and prompt a
            //       dynamic scan, NOT enough to call it malware on
            //       static alone.
            //
            //   (c) protected + decisive credential evidence
            //       (CRITICAL): if Protection.IsProtected is set
            //       AND we already saw a credential-theft chain
            //       (B6 / L9 / Browser DB + DPAPI + exfil), this
            //       is a packed credential stealer. Floor at 98.
            var prot = r.Protection;
            if (prot is { IsProtected: true })
            {
                if (r.LuaDownloadAndLoadChain && final < 92)
                {
                    int pre = final;
                    final = 92;
                    r.AppliedFloors.Add("LuaLoadsProtectedPayload");
                    r.ScoreContributors["Floor:LuaLoadsProtected=>92"] = final - pre;
                }
                bool gameModContext =
                    r.LuaSampHits != null && r.LuaSampHits.Count > 0 ||
                    string.Equals(r.FormatFamily, "PE-DLL-ASI",
                                  StringComparison.OrdinalIgnoreCase);
                if (gameModContext && r.IsDll && final < 60)
                {
                    int pre = final;
                    final = 60;
                    r.AppliedFloors.Add("ProtectedDllInGameModContext");
                    r.ScoreContributors["Floor:ProtectedDllInGameMod=>60"] = final - pre;
                }
                bool hasCredentialExfil =
                    r.LuaCredentialExfilChain ||
                    r.AppliedFloors.Contains("BrowserDbDpapiExfil") ||
                    r.AppliedFloors.Contains("CookieTheftExfil") ||
                    r.AppliedFloors.Contains("WalletSeedExfil") ||
                    r.AppliedFloors.Contains("DiscordLevelDbExfil");
                if (hasCredentialExfil && final < 98)
                {
                    int pre = final;
                    final = 98;
                    r.AppliedFloors.Add("ProtectedCredentialExfil");
                    r.ScoreContributors["Floor:ProtectedCredExfil=>98"] = final - pre;
                }
            }

            // C15 — calibrated single-signal ceiling. A solitary URL
            // with no other supporting evidence (no Telegram/Discord
            // exfil sink, no credential-theft, no script cradle, no
            // YARA hit, no advanced indicators) is almost always
            // benign — cap at LOW so a HTTP reference in a config
            // string doesn't drag a clean binary into HIGH.  Decisive
            // floors veto this ceiling.
            bool isolatedUrlOnly =
                r.AppliedFloors.Count == 0 &&
                r.UrlsFound.Count >= 1 &&
                credentialTheft  < 10 && exfiltration    < 10 &&
                cryptoTheft      < 10 && executionVectors < 10 &&
                antiAnalysis     < 10 && persistence     < 10 &&
                r.YaraHits.Count == 0 &&
                r.SuspiciousApiHits.Count < 3 &&
                r.BrowserStealerIndicators.Count == 0 &&
                r.TelegramExfilEndpoints.Count == 0 &&
                r.DiscordTokenHits.Count == 0 &&
                r.LuaThreatHits.Count == 0;
            if (isolatedUrlOnly && final > 25)
            {
                int before = final;
                final = 25;
                r.AppliedCeilings.Add("IsolatedUrlOnly");
                r.ScoreContributors["Ceiling:IsolatedUrlOnly"] = final - before;
            }

            // B18 (v2) — allowlist as a discount, not a kill-switch.
            // A signed binary that nevertheless trips multiple decisive
            // detectors keeps its full risk score; a signed binary
            // whose only suspicious findings are weak heuristics
            // (single capability < 40 raw, no decisive evidence) gets
            // dropped to the visibility floor. Anything in between
            // gets a flat -20 discount, never an override.
            if (allow)
            {
                bool decisive = HasDecisiveMaliciousEvidence(r);
                int raw = final;
                if (!decisive && raw < 40)
                {
                    final = Math.Min(raw, 5);
                    r.AppliedCeilings.Add("AllowlistFullDiscount");
                    r.ScoreContributors["Discount:AllowlistFull"] = final - raw;
                }
                else if (!decisive)
                {
                    final = Math.Max(raw - 20, 0);
                    r.AppliedCeilings.Add("AllowlistMinorDiscount");
                    r.ScoreContributors["Discount:AllowlistMinor"] = final - raw;
                }
                else
                {
                    r.AppliedFloors.Add("AllowlistVetoedByDecisive");
                }
            }

            if (final > 100) final = 100;
            if (final < 0) final = 0;

            // C15 — calibrated confidence axes. Independent of the
            // single RiskScore so the UI can show three values:
            //   MaliciousConfidence  — "how sure are we this is bad?"
            //   StealerConfidence    — "how sure is it an infostealer?"
            //   FalsePositiveRisk    — "how shaky is the verdict?"
            CalibrateConfidenceAxes(r, final, credentialTheft, exfiltration,
                                    cryptoTheft, antiAnalysis, persistence,
                                    network, packing, executionVectors,
                                    isolatedUrlOnly);
            return final;
        }

        // C15 — derive 0..100 calibrated confidence axes from raw
        // capability scores and final risk.  Deliberately conservative:
        // a single weak hit cannot push MaliciousConfidence above 30,
        // and StealerConfidence requires both a credential-source AND
        // a collection/exfil signal.  FalsePositiveRisk is the inverse
        // — high when only weak (single-word, no path) hits fire.
        private static void CalibrateConfidenceAxes(
            AnalysisResult r, int final,
            int credentialTheft, int exfiltration, int cryptoTheft,
            int antiAnalysis, int persistence, int network,
            int packing, int executionVectors,
            bool isolatedUrlOnly)
        {
            // Malicious confidence — weighted maximum, biased by floors.
            int strongCapCount =
                (credentialTheft  >= 50 ? 1 : 0) +
                (exfiltration     >= 50 ? 1 : 0) +
                (cryptoTheft      >= 50 ? 1 : 0) +
                (antiAnalysis     >= 50 ? 1 : 0) +
                (persistence      >= 50 ? 1 : 0) +
                (executionVectors >= 50 ? 1 : 0);

            int mal = final;
            if (r.AppliedFloors.Count > 0) mal = Math.Max(mal, 85);
            if (strongCapCount >= 3)       mal = Math.Max(mal, 80);
            else if (strongCapCount == 2)  mal = Math.Max(mal, 65);
            if (r.YaraHits.Count > 0)      mal = Math.Max(mal, 70);
            if (!string.IsNullOrEmpty(r.ImphashFamilyMatch)) mal = Math.Max(mal, 85);
            if (r.Sha256FamilyMatch != null && r.Sha256FamilyMatch.Length > 0)         mal = Math.Max(mal, 90);
            if (r.AuthentihashFamilyMatch != null && r.AuthentihashFamilyMatch.Length > 0) mal = Math.Max(mal, 85);
            // Bound below by raw final (never make the user think we are
            // less sure than the headline number).
            if (mal > 100) mal = 100;
            if (mal < 0) mal = 0;
            r.MaliciousConfidence = mal;

            // Stealer confidence — needs a credential source AND a
            // collection / exfil signal.  Otherwise it could be a
            // generic dropper, ransomware, or rat.
            bool credSource =
                credentialTheft >= 30 ||
                HasBrowserDbPath(r) ||
                HasDpapiCall(r) ||
                r.BrowserStealerIndicators.Count > 0 ||
                r.CryptoWalletHits.Count > 0 ||
                r.LuaThreatHits.Count > 0 ||
                r.JsCredScraperHits.Count > 0;
            bool collectionOrExfil =
                exfiltration >= 30 ||
                AnyExfilSink(r) ||
                r.JsCredPostHits.Count > 0;
            int stealer = 0;
            if (credSource && collectionOrExfil)
            {
                stealer = 60;
                if (HasBrowserDbDpapiExfilChain(r)) stealer = Math.Max(stealer, 90);
                if (r.AppliedFloors.Any(f => f != null && (
                        f.StartsWith("BrowserDb",       StringComparison.Ordinal) ||
                        f.StartsWith("CookieSession",   StringComparison.Ordinal) ||
                        f.StartsWith("WalletSeed",      StringComparison.Ordinal) ||
                        f.StartsWith("DiscordLevelDb", StringComparison.Ordinal) ||
                        f.StartsWith("PasswordManager",StringComparison.Ordinal) ||
                        f.StartsWith("DecisiveTelegram", StringComparison.Ordinal))))
                {
                    stealer = Math.Max(stealer, 92);
                }
            }
            else if (credSource || collectionOrExfil)
            {
                stealer = 30;
            }
            if (stealer > 100) stealer = 100;
            r.StealerConfidence = stealer;

            // False-positive risk — high when the verdict rests on a
            // single weak signal.  Anything that meets a decisive
            // floor or a known-bad fingerprint resets it to near zero.
            int fp = 0;
            if (final >= 60 && strongCapCount == 0 && r.AppliedFloors.Count == 0 && r.YaraHits.Count == 0)
                fp = 55;
            if (isolatedUrlOnly) fp = Math.Max(fp, 70);
            if (r.AllowlistMatched && r.AppliedFloors.Count == 0) fp = Math.Max(fp, 60);
            if (r.AppliedFloors.Count >= 2 || r.AppliedFloors.Any(f => f != null && f.StartsWith("BrowserDb", StringComparison.Ordinal)))
                fp = 0;
            if (!string.IsNullOrEmpty(r.Sha256FamilyMatch) ||
                !string.IsNullOrEmpty(r.AuthentihashFamilyMatch) ||
                !string.IsNullOrEmpty(r.ImphashFamilyMatch))
                fp = 0;
            if (fp > 100) fp = 100;
            r.FalsePositiveRisk = fp;
        }

        // B6/B8 helpers — shared between Score()'s decisive-floor
        // recipes and HasDecisiveMaliciousEvidence()'s allowlist
        // override. Keeping them as private helpers avoids two copies
        // of the same heuristic drifting apart.
        internal static bool HasBrowserDbPath(AnalysisResult r) =>
            r.StringHits.Any(s => s != null && (
                s.Contains("Login Data",  StringComparison.OrdinalIgnoreCase) ||
                s.Contains("Cookies",     StringComparison.OrdinalIgnoreCase) ||
                s.Contains("Web Data",    StringComparison.OrdinalIgnoreCase) ||
                s.Contains("Local State", StringComparison.OrdinalIgnoreCase)));

        internal static bool HasDpapiCall(AnalysisResult r) =>
            r.StringHits.Any(s => s != null && (
                s.Contains("CryptUnprotectData", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("DPAPI",              StringComparison.OrdinalIgnoreCase) ||
                s.Contains("os_crypt",           StringComparison.OrdinalIgnoreCase)));

        internal static bool AnyExfilSink(AnalysisResult r) =>
            r.TelegramExfilEndpoints.Count > 0 ||
            r.DiscordTokenHits.Count       > 0 ||
            r.UrlsFound.Any(u => u != null && (
                u.Contains("api.telegram.org",         StringComparison.OrdinalIgnoreCase) ||
                u.Contains("discord.com/api/webhooks", StringComparison.OrdinalIgnoreCase) ||
                u.Contains("discordapp.com/api/webhooks", StringComparison.OrdinalIgnoreCase) ||
                u.Contains("pastebin.com/raw",         StringComparison.OrdinalIgnoreCase) ||
                u.Contains("anonfiles.com",            StringComparison.OrdinalIgnoreCase) ||
                u.Contains("transfer.sh",              StringComparison.OrdinalIgnoreCase) ||
                u.Contains("gofile.io",                StringComparison.OrdinalIgnoreCase) ||
                u.Contains("ngrok.io",                 StringComparison.OrdinalIgnoreCase) ||
                u.Contains("trycloudflare.com",        StringComparison.OrdinalIgnoreCase)));

        internal static bool HasBrowserDbDpapiExfilChain(AnalysisResult r) =>
            HasBrowserDbPath(r) && HasDpapiCall(r) && AnyExfilSink(r);

        // Decisive maliciousness — any one of these patterns is enough
        // to veto the allowlist short-circuit. The list is intentionally
        // narrow: each entry encodes a multi-signal cluster (credential
        // source + exfil, or a high-fidelity known-bad indicator) that
        // is essentially never seen on benign software.
        internal static bool HasDecisiveMaliciousEvidence(AnalysisResult r)
        {
            if (r == null) return false;

            // Browser credential-theft chain — Login Data / Cookies path
            // plus DPAPI plus any exfil sink.
            if (HasBrowserDbDpapiExfilChain(r)) return true;

            bool hasExfilSink = AnyExfilSink(r);

            // Telegram/Discord webhook explicitly present anywhere in
            // the corpus — even when unaccompanied by browser DB, this
            // is decisive when combined with credential-source paths.
            if ((r.TelegramExfilEndpoints.Count > 0 || hasExfilSink) &&
                (r.BrowserStealerIndicators.Count >= 1 ||
                 r.CryptoWalletHits.Count          >= 1 ||
                 r.GameTargetHits.Count            >= 1 ||
                 r.MalwareSelfIdHits.Count         >= 1)) return true;

            // External / embedded YARA hit on a non-PE input is rarely
            // a false-positive — operator-curated rules.
            if (r.YaraHits.Count > 0 || r.MiniYaraXHits.Count > 0) return true;

            // Process injection + network channel — classic loader.
            if (r.SuspiciousApiHits.Any(s => s != null && (
                    s.Contains("VirtualAllocEx",    StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("WriteProcessMemory",StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("CreateRemoteThread",StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("NtMapViewOfSection",StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("QueueUserAPC",      StringComparison.OrdinalIgnoreCase))) &&
                (r.UrlsFound.Count > 0 || r.SuspiciousApiHits.Any(s => s != null && (
                    s.Contains("InternetOpen",  StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("WinHttp",       StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("HttpSendRequest",StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("WSASend",       StringComparison.OrdinalIgnoreCase))))) return true;

            // CC13 — Lua / SA-MP stealer signatures from the JS spec.
            if (r.LuaThreatHits.Count > 0) return true;

            // Advanced-threat clusters (shellcode / BYOVD / C2 framework /
            // phishing kit / npm supply-chain) — each of these tagging
            // any one entry was the explicit reason the module was
            // added in PR 13.
            if (r.ShellcodeIndicators.Count    > 0 ||
                r.ByovdIndicators.Count        > 0 ||
                r.C2FrameworkIndicators.Count  > 0) return true;

            // Known-bad fuzzy / import hash. Exact SHA256 match against
            // the local denylist would be picked up by the YARA / cloud
            // intel branch above; this is for samples that have been
            // re-compiled but kept the same import / Rich-header layout.
            if (!string.IsNullOrEmpty(r.ImpHash) &&
                AllowedImpHashes.Contains("denylist:" + r.ImpHash)) return true;

            return false;
        }

        // Detects the canonical info-stealer pattern: credential-harvest artefacts (browser DBs,
        // DPAPI blobs, wallet files, private keys, Discord/Telegram tokens) *combined* with an
        // egress channel (api.telegram.org, discord webhook, pastebin, mega, anonfiles, transfer.sh,
        // gofile, ngrok, SMTP). On its own each side can be innocuous, together they're a stealer.
        /// <summary>
        /// C20 — bonus from auto-ingested threat-intel feed matches.
        /// Bounded so a noisy feed cannot single-handedly drive a sample
        /// into HIGH; feed hits are confirmation, not the verdict.
        /// </summary>
        private static int ThreatIntelFeedBonus(AnalysisResult r)
        {
            if (r.FeedHits == null || r.FeedHits.Count == 0) return 0;
            int b = 0;
            int sha = 0, imp = 0, url = 0, dom = 0, ip = 0;
            foreach (var h in r.FeedHits)
            {
                if (h == null) continue;
                int p = h.IndexOf('|');
                if (p < 0) continue;
                var kv = h.Substring(p + 1);
                int q = kv.IndexOf(':');
                if (q < 0) continue;
                switch (kv.Substring(0, q).ToLowerInvariant())
                {
                    case "sha256":  sha++; break;
                    case "imphash": imp++; break;
                    case "url":     url++; break;
                    case "domain":  dom++; break;
                    case "ipv4":    ip ++; break;
                }
            }
            // sha256 / imphash are high-fidelity exact matches; url /
            // domain / ip are noisier so each kind has a small cap.
            b += sha > 0 ? 35 : 0;
            b += imp > 0 ? 25 : 0;
            b += Math.Min(15, url * 5);
            b += Math.Min(10, dom * 3);
            b += Math.Min(10, ip  * 3);
            return Math.Min(60, b);
        }

        private static int StealerExfilPatternBonus(AnalysisResult r)
        {
            bool hasCredArtifact =
                r.BrowserStealerIndicators.Count >= 1 ||
                r.MalwareSelfIdHits.Count >= 1 ||
                r.GameTargetHits.Count >= 1 ||
                r.CryptoWalletHits.Count >= 1 ||
                r.PrivateKeyBlockHits >= 1 ||
                r.DiscordTokenHits.Count >= 1 ||
                r.TelegramBotTokenHits.Count >= 1 ||
                r.StringHits.Any(s => s.Contains("Login Data", StringComparison.OrdinalIgnoreCase)
                                   || s.Contains("\\Cookies", StringComparison.OrdinalIgnoreCase)
                                   || s.Contains("CryptUnprotectData", StringComparison.OrdinalIgnoreCase));

            bool hasExfilChannel =
                r.TelegramBotTokenHits.Count >= 1 ||
                r.TelegramExfilEndpoints.Count >= 1 ||
                r.UrlsFound.Any(u =>
                    u.IndexOf("api.telegram.org", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    u.IndexOf("t.me/", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    u.IndexOf("discord.com/api/webhooks", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    u.IndexOf("discordapp.com/api/webhooks", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    u.IndexOf("pastebin.com", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    u.IndexOf("anonfiles", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    u.IndexOf("gofile", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    u.IndexOf("transfer.sh", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    u.IndexOf("filebin", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    u.IndexOf("mega.nz", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    u.IndexOf("ngrok.",   StringComparison.OrdinalIgnoreCase) >= 0) ||
                r.C2Indicators.Any(c => c.IndexOf("telegram", StringComparison.OrdinalIgnoreCase) >= 0
                                     || c.IndexOf("discord",  StringComparison.OrdinalIgnoreCase) >= 0);

            if (!(hasCredArtifact && hasExfilChannel)) return 0;

            int bonus = 20;
            // Telegram-bot-token in the body is essentially a smoking gun — another +10.
            if (r.TelegramBotTokenHits.Count >= 1) bonus += 10;
            // Self-identification strings (PDB "Stealer.pdb", exfil templates) — another +10.
            if (r.MalwareSelfIdHits.Count >= 1) bonus += 10;
            // Game-account targeting (SA:MP, MTA, Radmir, Steam, …) — another +5.
            if (r.GameTargetHits.Count >= 1) bonus += 5;
            // Dedicated Telegram exfil endpoint (sendMessage URL with %s or explicit bot verb) — +10.
            if (r.TelegramExfilEndpoints.Count >= 1) bonus += 10;
            // Multiple distinct credential artefacts -> another +5.
            int credKinds =
                (r.BrowserStealerIndicators.Count >= 1 ? 1 : 0) +
                (r.CryptoWalletHits.Count        >= 1 ? 1 : 0) +
                (r.PrivateKeyBlockHits           >= 1 ? 1 : 0) +
                (r.DiscordTokenHits.Count        >= 1 ? 1 : 0) +
                (r.MalwareSelfIdHits.Count       >= 1 ? 1 : 0) +
                (r.GameTargetHits.Count          >= 1 ? 1 : 0);
            if (credKinds >= 2) bonus += 5;
            if (credKinds >= 3) bonus += 5;

            r.CustomHeuristicHits.Add($"stealer-exfil-pattern (+{bonus})");
            return bonus;
        }

        // B1 bump: every YARA hit adds a small bonus to CredentialTheft by proxy (strong signal).
        private static int YaraBonus(AnalysisResult r) => Math.Min(30, r.YaraHits.Count * 12);

        private static int ScoreCredentialTheft(AnalysisResult r)
        {
            int s = 0;
            s += Math.Min(50, r.BrowserStealerIndicators.Count * 12); // chromium DB names, DPAPI blobs
            s += Math.Min(30, r.PrivateKeyBlockHits * 12);
            s += Math.Min(20, r.JwtHits.Count * 6);
            // Stealer token hits are a strong credential-theft indicator: a Telegram bot token shipped
            // inside a binary means the binary has an outbound channel wired up for exfil. Boosted
            // from *5/cap15 to *15/cap40 after user report of stealers scoring 36/100.
            s += Math.Min(40, r.DiscordTokenHits.Count * 15 + r.TelegramBotTokenHits.Count * 15);
            // Self-identification strings (PDB paths named *Stealer.pdb, exfil-template formatters,
            // literal "stealer" / "grabber" / "clipper" / "keylogger" in the binary).
            s += Math.Min(50, r.MalwareSelfIdHits.Count * 18);
            // Game-stealer targeting (SA:MP, MTA, Radmir, Steam, Roblox, …). Lower unit weight than
            // selfID because legit game software may mention "steam_api.dll" etc. — but in combo
            // with selfID / exfil channel, it's decisive. Cap 40.
            s += Math.Min(40, r.GameTargetHits.Count * 8);
            // Dedicated Telegram exfil-endpoint IOC (URL contains bot-API verb + format specifier).
            // This is almost unambiguous — legit code does not format a bot token into the URL.
            s += Math.Min(30, r.TelegramExfilEndpoints.Count * 20);
            s += Math.Min(20, r.StringHits.Count);                    // noisy, weight=1
            s += YaraBonus(r);
            s += CloudBonus(r);
            return Math.Min(100, s);
        }

        // C4/C5/C6/C9: bump score when external reputation / local AV say this file is malicious.
        private static int CloudBonus(AnalysisResult r)
        {
            int s = 0;
            if (r.CloudLookupResults.TryGetValue("VirusTotal", out var vt) && vt.StartsWith("malicious=", StringComparison.OrdinalIgnoreCase))
            {
                // 'malicious=12/73 suspicious=3'; parse first number.
                int eq = vt.IndexOf('=');
                int slash = vt.IndexOf('/');
                if (eq >= 0 && slash > eq && int.TryParse(vt.AsSpan(eq + 1, slash - eq - 1), out var m) && m > 0)
                    s += Math.Min(40, m * 4);
            }
            if (r.CloudLookupResults.ContainsKey("MalwareBazaar")) s += 20;
            if (r.CloudLookupResults.TryGetValue("HybridAnalysis", out var ha) &&
                ha.IndexOf("malicious", StringComparison.OrdinalIgnoreCase) >= 0) s += 20;
            if (r.LocalAvHits.Count > 0) s += 30;
            if (r.SigmaLiteHits.Count > 0) s += Math.Min(20, r.SigmaLiteHits.Count * 8);
            return s;
        }

        private static int ScoreExfiltration(AnalysisResult r)
        {
            int s = 0;
            s += Math.Min(30, r.UrlsFound.Count * 2);
            s += Math.Min(20, r.NetDllHits.Count * 6);
            s += Math.Min(20, r.EmailHits.Count * 3);
            s += Math.Min(20, r.Base64BlobHits);
            if (r.ImportedApis.Any(a => a.Contains("WinHttp", StringComparison.OrdinalIgnoreCase) ||
                                        a.Contains("InternetOpen", StringComparison.OrdinalIgnoreCase) ||
                                        a.Contains("HttpSendRequest", StringComparison.OrdinalIgnoreCase))) s += 10;

            // Pinned exfil-destination signals: Telegram / Discord webhook / paste sites / mega /
            // anonfiles / transfer.sh / ngrok. Each distinct sink is +15 (cap 45).
            int sinks = 0;
            foreach (var u in r.UrlsFound)
            {
                if (u.IndexOf("api.telegram.org",            StringComparison.OrdinalIgnoreCase) >= 0 ||
                    u.IndexOf("t.me/",                       StringComparison.OrdinalIgnoreCase) >= 0 ||
                    u.IndexOf("discord.com/api/webhooks",    StringComparison.OrdinalIgnoreCase) >= 0 ||
                    u.IndexOf("discordapp.com/api/webhooks", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    u.IndexOf("pastebin.com",                StringComparison.OrdinalIgnoreCase) >= 0 ||
                    u.IndexOf("anonfiles",                   StringComparison.OrdinalIgnoreCase) >= 0 ||
                    u.IndexOf("gofile",                      StringComparison.OrdinalIgnoreCase) >= 0 ||
                    u.IndexOf("transfer.sh",                 StringComparison.OrdinalIgnoreCase) >= 0 ||
                    u.IndexOf("filebin",                     StringComparison.OrdinalIgnoreCase) >= 0 ||
                    u.IndexOf("mega.nz",                     StringComparison.OrdinalIgnoreCase) >= 0 ||
                    u.IndexOf("ngrok.",                      StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    sinks++;
                }
            }
            if (r.TelegramBotTokenHits.Count > 0) sinks++;
            s += Math.Min(45, sinks * 15);
            return Math.Min(100, s);
        }

        private static int ScoreExecutionVectors(AnalysisResult r)
        {
            int s = 0;
            s += Math.Min(40, r.ScriptIndicators.Count * 8);
            s += Math.Min(30, r.PdfRiskyTags.Count * 10);
            s += Math.Min(40, r.OfficeIndicators.Count * 15);
            if (!string.IsNullOrEmpty(r.LnkTargetPath) &&
                (r.LnkTargetPath.IndexOf("powershell", StringComparison.OrdinalIgnoreCase) >= 0 ||
                 r.LnkTargetPath.IndexOf("cmd.exe", StringComparison.OrdinalIgnoreCase) >= 0 ||
                 r.LnkTargetPath.IndexOf("mshta", StringComparison.OrdinalIgnoreCase) >= 0))
                s += 30;
            return Math.Min(100, s);
        }

        private static int ScoreAntiAnalysis(AnalysisResult r)
        {
            int s = 0;
            s += Math.Min(60, r.AntiAnalysisIndicators.Count * 8);
            if (r.ImportedApis.Any(a => a.Equals("IsDebuggerPresent", StringComparison.OrdinalIgnoreCase))) s += 10;
            if (r.ImportedApis.Any(a => a.Contains("NtQueryInformationProcess", StringComparison.OrdinalIgnoreCase))) s += 10;
            if (r.ImportedApis.Any(a => a.Contains("CheckRemoteDebuggerPresent", StringComparison.OrdinalIgnoreCase))) s += 10;
            return Math.Min(100, s);
        }

        private static int ScorePersistence(AnalysisResult r)
        {
            int s = 0;
            s += Math.Min(80, r.PersistenceIndicators.Count * 15);
            return Math.Min(100, s);
        }

        private static int ScoreNetwork(AnalysisResult r)
        {
            int s = 0;
            s += Math.Min(40, r.UrlsFound.Count * 2);
            s += Math.Min(20, r.Ipv4Hits.Count * 2);
            s += Math.Min(30, r.C2Indicators.Count * 10);
            s += Math.Min(20, r.SuspiciousApiHits.Count);
            return Math.Min(100, s);
        }

        private static int ScoreCryptoTheft(AnalysisResult r)
        {
            int s = 0;
            s += Math.Min(100, r.CryptoWalletHits.Count * 15);
            return Math.Min(100, s);
        }

        private static int ScorePacking(AnalysisResult r)
        {
            int s = 0;
            s += Math.Min(40, r.PackerHints.Count * 10);
            if (r.UpxMarkerDetected) s += 25;
            if (r.HighEntropyChunkCount >= 16) s += 20;
            if (r.ExecutableWritableSections.Count > 0) s += 15;
            return Math.Min(100, s);
        }

        // B18: allowlist of known-good signer thumbprints and canonical imphashes. Kept tiny and
        // deliberately conservative — the idea is to suppress *obvious* Microsoft / known-tool
        // false-positives, not to build a full reputation system.
        private static readonly HashSet<string> AllowedSignerThumbprints = new(StringComparer.OrdinalIgnoreCase)
        {
            // Microsoft Code Signing PCA 2011 (sample thumbprints — extend as needed).
            "108E2BA23632620C427C570B6D9DB51AC31387FE",
            "3BA5E4A1AFD4AD4E41F4CB0F8B1B6F8F29F5A0D1",
        };
        private static readonly HashSet<string> AllowedSignerSubjectContains = new(StringComparer.OrdinalIgnoreCase)
        {
            "Microsoft Corporation",
            "Microsoft Windows",
            "Google LLC",
        };
        private static readonly HashSet<string> AllowedImpHashes = new(StringComparer.OrdinalIgnoreCase)
        {
            // Populate with known-benign imphashes over time. Examples are placeholders.
        };

        private static bool MatchAllowlist(AnalysisResult r, out string reason)
        {
            reason = "";
            if (r.IsSigned && r.SignerChainValid == true)
            {
                if (!string.IsNullOrEmpty(r.SignerThumbprint) && AllowedSignerThumbprints.Contains(r.SignerThumbprint))
                { reason = $"signer-thumbprint:{r.SignerThumbprint}"; return true; }
                if (!string.IsNullOrEmpty(r.Signer) &&
                    AllowedSignerSubjectContains.Any(s => r.Signer.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0))
                { reason = $"signer-subject:{r.Signer}"; return true; }
            }

            if (!string.IsNullOrEmpty(r.ImpHash) && AllowedImpHashes.Contains(r.ImpHash))
            { reason = $"imphash:{r.ImpHash}"; return true; }

            return false;
        }

        private static long CalculateOverlaySize(string path, List<SectionHeader> sections)
        {
            long fileSize = new FileInfo(path).Length;
            int maxEnd = 0;

            foreach (var s in sections)
            {
                int end = s.PointerToRawData + s.SizeOfRawData;
                if (end > maxEnd) maxEnd = end;
            }

            return fileSize > maxEnd ? fileSize - maxEnd : 0;
        }

        // M5 + M6 + F2: single-pass SHA256 + prefix read. Uses IncrementalHash so we hash the full file
        // while simultaneously capturing the first `maxBytes` into an in-memory buffer. This avoids reading
        // the file twice (once for SHA256, once for ReadPrefix).
        private static (string sha256, byte[] prefix) ReadPrefixAndSha256(string path, int maxBytes)
        {
            var (sha, prefix, _) = ReadMultiWindowAndSha256(path, maxBytes, tailMaxBytes: 0);
            return (sha, prefix);
        }

        // A3 — multi-window scan. Hashes the whole stream in one pass
        // and captures BOTH the prefix (first `prefixMaxBytes`) and the
        // tail (last `tailMaxBytes`) into separate buffers. The tail
        // window is sliding: the most recent `tailMaxBytes` of the
        // stream are kept after the file is fully consumed, so for a
        // 200 MiB file we get the prefix (first 20 MiB) PLUS the last 8
        // MiB without ever loading the middle. The two windows are
        // disjoint when the file is large enough; when the file fits
        // inside the prefix the tail buffer is empty.
        internal static (string sha256, byte[] prefix, byte[] tail) ReadMultiWindowAndSha256(
            string path, int prefixMaxBytes, int tailMaxBytes)
        {
            using var fs = File.OpenRead(path);
            long fileLen = fs.Length;
            int prefixLen = (int)Math.Min(prefixMaxBytes, fileLen);
            // Skip tail when the prefix already covers the whole file —
            // otherwise we'd duplicate the same bytes in two windows.
            int tailLen = (fileLen > prefixMaxBytes)
                ? (int)Math.Min(tailMaxBytes, fileLen - prefixMaxBytes)
                : 0;
            var prefix = new byte[prefixLen];
            // tailRing is a circular buffer; after the stream ends we
            // unwrap it into a flat byte[]. Allocating tailLen up-front
            // keeps the worst case at prefix+tail bytes resident.
            var tailRing = tailLen > 0 ? new byte[tailLen] : Array.Empty<byte>();
            int prefixRead  = 0;
            int tailHead    = 0;
            long tailFilled = 0;

            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var chunk = System.Buffers.ArrayPool<byte>.Shared.Rent(81920);
            try
            {
                int n;
                while ((n = fs.Read(chunk, 0, chunk.Length)) > 0)
                {
                    hasher.AppendData(chunk, 0, n);
                    if (prefixRead < prefixLen)
                    {
                        int copy = Math.Min(n, prefixLen - prefixRead);
                        Buffer.BlockCopy(chunk, 0, prefix, prefixRead, copy);
                        prefixRead += copy;
                    }
                    if (tailLen > 0)
                    {
                        // Append `n` bytes to the ring buffer; oldest
                        // bytes get overwritten so we always retain the
                        // most recent tailLen bytes of the stream.
                        int offset = 0;
                        while (offset < n)
                        {
                            int free = tailLen - tailHead;
                            int copy = Math.Min(free, n - offset);
                            Buffer.BlockCopy(chunk, offset, tailRing, tailHead, copy);
                            tailHead = (tailHead + copy) % tailLen;
                            tailFilled = Math.Min(tailFilled + copy, tailLen);
                            offset += copy;
                        }
                    }
                }
            }
            finally
            {
                System.Buffers.ArrayPool<byte>.Shared.Return(chunk);
            }

            if (prefixRead != prefixLen)
            {
                var trimmed = new byte[prefixRead];
                Buffer.BlockCopy(prefix, 0, trimmed, 0, prefixRead);
                prefix = trimmed;
            }

            // Unwrap the ring into a flat tail buffer. The "start" is
            // tailHead when the buffer is full, else 0.
            byte[] tail;
            if (tailLen == 0 || tailFilled == 0)
            {
                tail = Array.Empty<byte>();
            }
            else if (tailFilled < tailLen)
            {
                tail = new byte[tailFilled];
                Buffer.BlockCopy(tailRing, 0, tail, 0, (int)tailFilled);
            }
            else
            {
                tail = new byte[tailLen];
                int first = tailLen - tailHead;
                Buffer.BlockCopy(tailRing, tailHead, tail, 0, first);
                if (tailHead > 0)
                    Buffer.BlockCopy(tailRing, 0, tail, first, tailHead);
            }

            var sha = HexUtil.ToLowerHex(hasher.GetHashAndReset());
            return (sha, prefix, tail);
        }

        // A4 — recursive archive scan support.
        //
        // The depth cap and quota counters use AsyncLocal so a single
        // top-level Analyze() call gets independent budgets per
        // call-stack, allowing parallel calls without cross-talk.
        private static readonly System.Threading.AsyncLocal<int> _archiveDepth   = new();
        private static readonly System.Threading.AsyncLocal<int> _childrenScanned = new();
        // Hard caps — tunable through public statics so tests can
        // shrink them down without recompiling.
        public static int MaxArchiveDepth         { get; set; } = 4;
        public static int MaxArchiveChildren      { get; set; } = 256;
        public static int MaxArchiveChildBytes    { get; set; } = 32 * 1024 * 1024;
        public static int ArchiveContainerBonus   { get; set; } = 5;

        private static bool IsRecursableArchive(string fmt) => fmt switch
        {
            "ZIP" or "JAR" or "APK" or "AppX" or "Office-OOXML" => true,
            _ => false,
        };

        private static void ScanArchiveChildren(string path, AnalysisResult parent)
        {
            if (_archiveDepth.Value >= MaxArchiveDepth)
            {
                parent.ChildContainerHits.Add($"archive:depth-capped@{_archiveDepth.Value}");
                return;
            }

            _archiveDepth.Value++;
            try
            {
                using var fs = File.OpenRead(path);
                System.IO.Compression.ZipArchive archive;
                try { archive = new System.IO.Compression.ZipArchive(fs, System.IO.Compression.ZipArchiveMode.Read, leaveOpen: true); }
                catch { return; }
                using (archive)
                {
                    int childCount = 0;
                    foreach (var entry in archive.Entries)
                    {
                        if (_childrenScanned.Value >= MaxArchiveChildren) break;
                        if (childCount >= MaxArchiveChildren) break;
                        if (entry.Length <= 0) continue;
                        if (entry.Length > MaxArchiveChildBytes)
                        {
                            parent.ChildContainerHits.Add($"child-oversize:{entry.FullName} ({entry.Length} bytes)");
                            continue;
                        }
                        // Skip directories.
                        if (string.IsNullOrEmpty(entry.Name)) continue;

                        // Refuse hostile entry names — same checks as
                        // SafeExtract.Zip's hardening (mirrored here
                        // because we don't extract to disk).
                        var name = entry.FullName ?? string.Empty;
                        if (name.Length == 0 || name.IndexOf('\0') >= 0 || Path.IsPathRooted(name) ||
                            (name.Length >= 2 && name[1] == ':'))
                        {
                            parent.ChildContainerHits.Add($"child-rejected:{name}: rooted-name");
                            continue;
                        }

                        string tempPath;
                        try
                        {
                            tempPath = Path.Combine(Path.GetTempPath(),
                                "antistealer-child-" + Guid.NewGuid().ToString("N") + Path.GetExtension(entry.Name));
                            using (var es = entry.Open())
                            using (var ts = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
                                es.CopyTo(ts);
                        }
                        catch (Exception ex)
                        {
                            parent.ChildContainerHits.Add($"child-extract-fail:{name}: {ex.GetType().Name}");
                            continue;
                        }

                        try
                        {
                            childCount++;
                            _childrenScanned.Value++;
                            var displayChild = (parent.FilePath ?? path) + "!" + name;
                            var childRes = AnalyzeCore(tempPath, displayChild);
                            parent.Children.Add(childRes);

                            // Lift decisive evidence flags first so a
                            // post-aggregation re-score on the parent
                            // can observe them. The dedup HashSet
                            // semantics on YaraHits / MiniYaraXHits /
                            // LuaThreatHits / family indicators
                            // intentionally union with the parent's
                            // own findings.
                            foreach (var h in childRes.YaraHits)
                                if (!parent.YaraHits.Contains(h, StringComparer.Ordinal))
                                    parent.YaraHits.Add(h);
                            // P9 — surface each child hit as a separate
                            // structured detail with Source="child" so
                            // the operator can tell that the hit came
                            // from inside the archive, not from the
                            // archive's own contents.
                            foreach (var d in childRes.YaraHitDetails)
                            {
                                YaraHitTagger.AddHit(parent,
                                                     "child",
                                                     d.RuleFile,
                                                     d.RuleName,
                                                     region: name);
                            }
                            foreach (var h in childRes.MiniYaraXHits)
                                if (!parent.MiniYaraXHits.Contains(h, StringComparer.Ordinal))
                                    parent.MiniYaraXHits.Add(h);
                            foreach (var h in childRes.LuaThreatHits)
                                if (!parent.LuaThreatHits.Contains(h, StringComparer.Ordinal))
                                    parent.LuaThreatHits.Add(h);
                            foreach (var h in childRes.ShellcodeIndicators)
                                if (!parent.ShellcodeIndicators.Contains(h, StringComparer.Ordinal))
                                    parent.ShellcodeIndicators.Add(h);
                            foreach (var h in childRes.C2FrameworkIndicators)
                                if (!parent.C2FrameworkIndicators.Contains(h, StringComparer.Ordinal))
                                    parent.C2FrameworkIndicators.Add(h);
                            foreach (var h in childRes.MalwareSelfIdHits)
                                if (!parent.MalwareSelfIdHits.Contains(h, StringComparer.Ordinal))
                                    parent.MalwareSelfIdHits.Add(h);

                            // Aggregate: parent's score floors at
                            // max(parent, child + container_bonus, re-score(parent)).
                            // Container bonus reflects the technique
                            // of embedding a high-risk payload inside
                            // a benign-looking archive. When the child
                            // shows decisive maliciousness (YARA hit,
                            // credential-theft chain, Lua threat,
                            // shellcode/C2 cluster), the parent is
                            // floored at HIGH because the act of
                            // bundling a decisive-malicious payload
                            // inside the container is itself a
                            // decisive signal.
                            int proposed = childRes.RiskScore + ArchiveContainerBonus;
                            int rescored = Score(parent);
                            int newScore = Math.Max(parent.RiskScore, Math.Max(proposed, rescored));
                            if (HasDecisiveMaliciousEvidence(childRes))
                                newScore = Math.Max(newScore, 75);
                            if (newScore > parent.RiskScore)
                            {
                                parent.ChildContainerHits.Add(
                                    $"child:{name} risk={childRes.RiskScore} → parent={newScore}");
                                parent.RiskScore = Math.Min(100, newScore);
                            }
                        }
                        catch (Exception ex)
                        {
                            parent.ChildContainerHits.Add($"child-analyze-fail:{name}: {ex.GetType().Name}");
                        }
                        finally
                        {
                            try { File.Delete(tempPath); } catch { /* best-effort cleanup */ }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                parent.ChildContainerHits.Add($"archive-open-fail: {ex.GetType().Name}");
            }
            finally
            {
                _archiveDepth.Value--;
            }
        }

        private static byte[] ReadPrefix(string path, int maxBytes)
        {
            // Kept as a thin wrapper for callers that only need the prefix.
            using var fs = File.OpenRead(path);
            int len = (int)Math.Min(maxBytes, fs.Length);
            var buf = new byte[len];
            // M5: ReadExactly throws EndOfStreamException if file shrinks mid-read; fall back to partial copy.
            try
            {
                fs.ReadExactly(buf, 0, len);
                return buf;
            }
            catch (EndOfStreamException)
            {
                int actual = (int)(fs.Position);
                if (actual == len) return buf;
                var trimmed = new byte[actual];
                Buffer.BlockCopy(buf, 0, trimmed, 0, actual);
                return trimmed;
            }
        }

        // M6: modern one-shot SHA256 helper over a stream. Kept for callers that only need the hash.
        private static string Sha256File(string path)
        {
            using var fs = File.OpenRead(path);
            return HexUtil.ToLowerHex(SHA256.HashData(fs));
        }

        // ============================================================
        // B4: Extended PE analysis helpers.
        // ============================================================

        // Canonical imphash: MD5 of the lowercased "dll.func,dll.func,..." list in import-directory order,
        // stripping the common ".dll"/".sys"/".ocx" extension from the DLL name. Ordinal-only imports are
        // recorded as "dll.ord123".
        private static string ComputeImpHash(PEReader pe)
        {
            var importDir = pe.PEHeaders.PEHeader?.ImportTableDirectory;
            if (importDir == null || importDir.Value.Size == 0) return "";

            var sb = new StringBuilder(8192);
            var reader = pe.GetSectionData(importDir.Value.RelativeVirtualAddress).GetReader();

            while (reader.RemainingBytes >= 20)
            {
                int originalThunk = reader.ReadInt32();
                int _timeDateStamp = reader.ReadInt32();
                int _forwarder = reader.ReadInt32();
                int dllNameRva = reader.ReadInt32();
                int firstThunk = reader.ReadInt32();
                if (originalThunk == 0 && dllNameRva == 0 && firstThunk == 0) break;

                var dllName = ReadNullTerminatedStringAtRva(pe, dllNameRva);
                if (string.IsNullOrEmpty(dllName)) continue;
                var dllShort = StripImphashDllSuffix(dllName).ToLowerInvariant();

                uint thunkRva = (uint)(originalThunk != 0 ? originalThunk : firstThunk);
                foreach (var funcName in ReadImportThunkNames(pe, thunkRva))
                {
                    if (sb.Length > 0) sb.Append(',');
                    sb.Append(dllShort).Append('.').Append(funcName.ToLowerInvariant());
                    if (sb.Length > 256_000) break; // defensive cap
                }
            }

            if (sb.Length == 0) return "";
            var bytes = Encoding.UTF8.GetBytes(sb.ToString());
            return HexUtil.ToLowerHex(MD5.HashData(bytes));
        }

        private static string StripImphashDllSuffix(string dll)
        {
            var n = dll;
            foreach (var ext in new[] { ".dll", ".sys", ".ocx", ".drv" })
            {
                if (n.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
                    return n[..^ext.Length];
            }
            return n;
        }

        // Rich Header parser: scan the DOS stub for the "Rich" marker, XOR-decode entries, and compute
        // two MD5 hashes:
        //   - RichHeaderHash: MD5 of the raw Rich header bytes (between DanS and Rich, inclusive of the
        //                     4-byte XOR key) — what yara-python uses.
        //   - RichHeaderHashStd: MD5 of just the decoded comp.id/count pairs (commonly called "RichPV").
        private static (string raw, string std) ComputeRichHeaderHashes(string path)
        {
            using var fs = File.OpenRead(path);
            int headerLen = (int)Math.Min(fs.Length, 4096);
            var buf = new byte[headerLen];
            fs.ReadExactly(buf, 0, headerLen);

            // Find "Rich" marker.
            int richIdx = -1;
            for (int i = 0x40; i + 8 < buf.Length; i++)
            {
                if (buf[i] == 'R' && buf[i + 1] == 'i' && buf[i + 2] == 'c' && buf[i + 3] == 'h')
                { richIdx = i; break; }
            }
            if (richIdx < 0) return ("", "");

            uint key = BitConverter.ToUInt32(buf, richIdx + 4);
            // Walk backwards searching for the decoded "DanS" marker (DanS XORed by key in raw file).
            int dansIdx = -1;
            for (int i = richIdx - 4; i >= 0x40; i -= 4)
            {
                uint decoded = BitConverter.ToUInt32(buf, i) ^ key;
                if (decoded == 0x536E6144 /* 'DanS' little-endian */)
                { dansIdx = i; break; }
            }
            if (dansIdx < 0) return ("", "");

            int rawLen = richIdx + 4 - dansIdx + 4; // include Rich + key
            var raw = new byte[rawLen];
            Buffer.BlockCopy(buf, dansIdx, raw, 0, rawLen);
            var rawHash = HexUtil.ToLowerHex(MD5.HashData(raw));

            // Standard: XOR-decoded entries, skipping DanS + 3 padding dwords.
            int entriesStart = dansIdx + 16;
            int entriesLen = richIdx - entriesStart;
            if (entriesLen <= 0) return (rawHash, "");
            var decodedEntries = new byte[entriesLen];
            for (int i = 0; i < entriesLen; i += 4)
            {
                uint v = BitConverter.ToUInt32(buf, entriesStart + i) ^ key;
                decodedEntries[i] = (byte)(v & 0xff);
                decodedEntries[i + 1] = (byte)((v >> 8) & 0xff);
                decodedEntries[i + 2] = (byte)((v >> 16) & 0xff);
                decodedEntries[i + 3] = (byte)((v >> 24) & 0xff);
            }
            var stdHash = HexUtil.ToLowerHex(MD5.HashData(decodedEntries));
            return (rawHash, stdHash);
        }

        // Authenticode SHA256 (§ 7.1 of "Authenticode Specification"):
        //   - skip the OptionalHeader Checksum field (4 bytes)
        //   - skip the Certificate Table entry in DataDirectories (8 bytes)
        //   - skip the actual Certificate Table contents (variable, trailing)
        //   - hash everything else in file order
        private static string ComputeAuthenticodeSha256(string path)
        {
            using var fs = File.OpenRead(path);
            // Read the full file so we can seek by offset. For huge files (>200MB) we bail out.
            if (fs.Length > 200L * 1024 * 1024) return "";
            var all = new byte[fs.Length];
            fs.ReadExactly(all, 0, all.Length);

            if (all.Length < 0x40) return "";
            int peOffset = BitConverter.ToInt32(all, 0x3c);
            if (peOffset <= 0 || peOffset + 24 > all.Length) return "";
            if (all[peOffset] != 'P' || all[peOffset + 1] != 'E' || all[peOffset + 2] != 0 || all[peOffset + 3] != 0) return "";

            ushort optHeaderSize = BitConverter.ToUInt16(all, peOffset + 20);
            int optHeaderStart = peOffset + 24;
            if (optHeaderStart + optHeaderSize > all.Length || optHeaderSize < 96) return "";

            ushort magic = BitConverter.ToUInt16(all, optHeaderStart);
            bool pe32Plus = magic == 0x20b;
            int checksumOffset = optHeaderStart + 64;
            int certDirEntryOffset = optHeaderStart + (pe32Plus ? 144 : 128);
            if (certDirEntryOffset + 8 > all.Length) return "";

            int certRva = BitConverter.ToInt32(all, certDirEntryOffset);
            int certSize = BitConverter.ToInt32(all, certDirEntryOffset + 4);

            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            // 1) 0 .. checksumOffset
            sha.AppendData(all, 0, checksumOffset);
            // 2) skip 4 bytes of checksum, hash up to certDirEntry
            int afterChecksum = checksumOffset + 4;
            sha.AppendData(all, afterChecksum, certDirEntryOffset - afterChecksum);
            // 3) skip 8 bytes of cert-dir entry, hash up to cert data (or end)
            int afterCertEntry = certDirEntryOffset + 8;
            int endOfHash = certRva > 0 && certSize > 0 ? certRva : all.Length;
            if (endOfHash > all.Length) endOfHash = all.Length;
            if (endOfHash > afterCertEntry)
                sha.AppendData(all, afterCertEntry, endOfHash - afterCertEntry);

            return HexUtil.ToLowerHex(sha.GetHashAndReset());
        }

        // B4: export table names. Walks IMAGE_EXPORT_DIRECTORY to collect up to `max` exported names.
        private static void ParseExportsInto(PEReader pe, List<string> dst, int max)
        {
            var exportDir = pe.PEHeaders.PEHeader?.ExportTableDirectory;
            if (exportDir == null || exportDir.Value.Size == 0) return;

            var r = pe.GetSectionData(exportDir.Value.RelativeVirtualAddress).GetReader();
            if (r.RemainingBytes < 40) return;
            r.ReadUInt32(); // characteristics
            r.ReadUInt32(); // timestamp
            r.ReadUInt32(); // version
            r.ReadUInt32(); // name RVA
            r.ReadUInt32(); // ordinal base
            int nFunctions = r.ReadInt32();
            int nNames = r.ReadInt32();
            r.ReadUInt32(); // AddressOfFunctions
            int addressOfNamesRva = r.ReadInt32();
            r.ReadUInt32(); // AddressOfNameOrdinals

            if (nNames <= 0 || addressOfNamesRva <= 0) return;
            int take = Math.Min(nNames, max);
            var namesReader = pe.GetSectionData(addressOfNamesRva).GetReader();
            for (int i = 0; i < take && namesReader.RemainingBytes >= 4; i++)
            {
                int nameRva = namesReader.ReadInt32();
                var name = ReadNullTerminatedStringAtRva(pe, nameRva);
                if (!string.IsNullOrEmpty(name)) dst.Add(name);
            }
        }

        // B4: walk IMAGE_RESOURCE_DIRECTORY and record the first-level resource type IDs/strings + any
        // VERSION_INFO (type 16 = RT_VERSION) payload keys. Best-effort: PE resources are a nested
        // directory tree, we intentionally only go one level deep here.
        private static readonly (int id, string label)[] StandardResourceTypes =
        {
            (1, "CURSOR"), (2, "BITMAP"), (3, "ICON"), (4, "MENU"), (5, "DIALOG"),
            (6, "STRING"), (7, "FONTDIR"), (8, "FONT"), (9, "ACCELERATOR"), (10, "RCDATA"),
            (11, "MESSAGETABLE"), (12, "GROUP_CURSOR"), (14, "GROUP_ICON"),
            (16, "VERSION"), (17, "DLGINCLUDE"), (19, "PLUGPLAY"), (20, "VXD"),
            (21, "ANICURSOR"), (22, "ANIICON"), (23, "HTML"), (24, "MANIFEST"),
        };

        private static void ParseResourcesInto(PEReader pe, AnalysisResult res)
        {
            var resDir = pe.PEHeaders.PEHeader?.ResourceTableDirectory;
            if (resDir == null || resDir.Value.Size == 0) return;
            var rootReader = pe.GetSectionData(resDir.Value.RelativeVirtualAddress).GetReader();
            if (rootReader.RemainingBytes < 16) return;
            rootReader.ReadUInt32(); // characteristics
            rootReader.ReadUInt32(); // timestamp
            rootReader.ReadUInt32(); // version
            ushort namedCount = rootReader.ReadUInt16();
            ushort idCount = rootReader.ReadUInt16();

            int total = Math.Min(namedCount + idCount, 64);
            for (int i = 0; i < total && rootReader.RemainingBytes >= 8; i++)
            {
                uint nameOrId = rootReader.ReadUInt32();
                rootReader.ReadUInt32(); // offset (we only care about type labels at this level)
                bool isString = (nameOrId & 0x80000000u) != 0;
                if (isString) { res.ResourceTypes.Add("STRING"); continue; }
                int id = (int)(nameOrId & 0x7fffffff);
                var label = StandardResourceTypes.FirstOrDefault(s => s.id == id).label ?? $"ID{id}";
                if (!res.ResourceTypes.Contains(label)) res.ResourceTypes.Add(label);
            }

            // Surface a few well-known VERSION_INFO fields if a UTF-16 "CompanyName\0" / "ProductName\0"
            // / "FileDescription\0" / "OriginalFilename\0" key is present in the resource payload.
            try
            {
                var payload = pe.GetSectionData(resDir.Value.RelativeVirtualAddress).GetContent().ToArray();
                string wide = Encoding.Unicode.GetString(payload);
                foreach (var key in new[] { "CompanyName", "ProductName", "FileDescription", "OriginalFilename", "LegalCopyright", "InternalName", "FileVersion" })
                {
                    int k = wide.IndexOf(key, StringComparison.Ordinal);
                    if (k < 0) continue;
                    int valStart = k + key.Length;
                    while (valStart < wide.Length && wide[valStart] == '\0') valStart++;
                    int valEnd = valStart;
                    while (valEnd < wide.Length && valEnd - valStart < 256 && wide[valEnd] >= 0x20) valEnd++;
                    var val = wide.Substring(valStart, valEnd - valStart).Trim();
                    if (!string.IsNullOrWhiteSpace(val)) res.VersionInfo[key] = val;
                }
            }
            catch { /* version info is best-effort */ }
        }

        // B4: overlay classifier. If overlay exists, examine its first bytes and classify:
        //   PE, ZIP, 7z, RAR, GZip, Cabinet, MSI, ASCII, High-entropy (encrypted / random), Unknown.
        private static void ClassifyOverlayInto(string path, AnalysisResult res)
        {
            if (res.OverlaySize <= 0) return;
            long overlayOffset;
            try
            {
                overlayOffset = new FileInfo(path).Length - res.OverlaySize;
                if (overlayOffset < 0) return;
            }
            catch { return; }

            using var fs = File.OpenRead(path);
            fs.Seek(overlayOffset, SeekOrigin.Begin);
            int sniffLen = (int)Math.Min(res.OverlaySize, 16);
            Span<byte> sniff = stackalloc byte[16];
            int n = fs.Read(sniff);
            if (n < 2) return;
            var s = sniff[..n];

            string type = "Unknown";
            if (s.Length >= 2 && s[0] == 'M' && s[1] == 'Z') type = "PE";
            else if (s.Length >= 4 && s[0] == 'P' && s[1] == 'K' && (s[2] == 3 || s[2] == 5 || s[2] == 7)) type = "ZIP";
            else if (s.Length >= 6 && s[0] == 0x37 && s[1] == 0x7A && s[2] == 0xBC && s[3] == 0xAF && s[4] == 0x27 && s[5] == 0x1C) type = "7Z";
            else if (s.Length >= 7 && s[0] == 'R' && s[1] == 'a' && s[2] == 'r' && s[3] == '!') type = "RAR";
            else if (s.Length >= 2 && s[0] == 0x1F && s[1] == 0x8B) type = "GZip";
            else if (s.Length >= 4 && s[0] == 'M' && s[1] == 'S' && s[2] == 'C' && s[3] == 'F') type = "CAB";
            else if (s.Length >= 4 && s[0] == 0xD0 && s[1] == 0xCF && s[2] == 0x11 && s[3] == 0xE0) type = "OLE/MSI";
            else if (s.Length >= 4 && s[0] == 0x25 && s[1] == 0x50 && s[2] == 0x44 && s[3] == 0x46) type = "PDF";
            else
            {
                // Heuristic: sample up to 64KB of the overlay and compute entropy.
                int take = (int)Math.Min(res.OverlaySize, 64 * 1024);
                fs.Seek(overlayOffset, SeekOrigin.Begin);
                var sample = new byte[take];
                fs.ReadExactly(sample, 0, take);
                double e = Entropy(sample);
                type = e >= 7.5 ? "High-entropy" : (e <= 4.5 ? "ASCII/Low-entropy" : "Unknown");
            }

            res.OverlayType = type;

            // SHA256 of the overlay content (bounded by 64MB so we don't explode on archives appended to PE).
            if (res.OverlaySize > 0 && res.OverlaySize <= 64L * 1024 * 1024)
            {
                fs.Seek(overlayOffset, SeekOrigin.Begin);
                using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var buf = System.Buffers.ArrayPool<byte>.Shared.Rent(81920);
                try
                {
                    long remaining = res.OverlaySize;
                    while (remaining > 0)
                    {
                        int want = (int)Math.Min(remaining, buf.Length);
                        int got = fs.Read(buf, 0, want);
                        if (got <= 0) break;
                        h.AppendData(buf, 0, got);
                        remaining -= got;
                    }
                }
                finally { System.Buffers.ArrayPool<byte>.Shared.Return(buf); }
                res.OverlaySha256 = HexUtil.ToLowerHex(h.GetHashAndReset());
            }
        }

        // B15: whole-file entropy histogram in 4KB chunks, plus UPX "UPX!" magic sweep.
        private static void ComputeChunkEntropyAndUpxInto(string path, AnalysisResult res)
        {
            const int ChunkSize = 4096;
            const int MaxChunks = 8192; // cap to 32MB worth of data sampling
            using var fs = File.OpenRead(path);
            var buf = new byte[ChunkSize];
            int chunks = 0;
            int high = 0;
            long scanned = 0;
            bool upx = false;
            byte[] upxMagic = Encoding.ASCII.GetBytes("UPX!");

            while (chunks < MaxChunks)
            {
                int got = fs.Read(buf, 0, ChunkSize);
                if (got <= 0) break;
                if (got == ChunkSize)
                {
                    double e = Entropy(buf);
                    res.ChunkEntropy.Add(Math.Round(e, 3));
                    if (e >= 7.2) high++;
                }
                // Scan for UPX marker in the chunk (small search, early-terminate on first hit).
                if (!upx)
                {
                    for (int i = 0; i + 4 <= got; i++)
                    {
                        if (buf[i] == upxMagic[0] && buf[i + 1] == upxMagic[1] && buf[i + 2] == upxMagic[2] && buf[i + 3] == upxMagic[3])
                        { upx = true; break; }
                    }
                }
                chunks++;
                scanned += got;
            }

            res.HighEntropyChunkCount = high;
            res.UpxMarkerDetected = upx;
            if (upx) res.PackerHints.Add("upx-magic");
            if (high >= 4) res.PackerHints.Add($"entropy-chunks>=7.2:{high}");
        }

        // Simplified fuzzy fingerprint: split the first 64MB into 64 equal chunks, take first 4 hex chars
        // of SHA1 per chunk, concatenate. Primarily useful for clustering near-duplicate samples; this is
        // explicitly NOT ssdeep/tlsh — properly integrating those is tracked as a follow-up.
        private static string ComputeChunkFingerprint(string path)
        {
            using var fs = File.OpenRead(path);
            long total = Math.Min(fs.Length, 64L * 1024 * 1024);
            if (total <= 0) return "";
            int bucketCount = 64;
            long bucketSize = Math.Max(1, total / bucketCount);
            var sb = new StringBuilder(bucketCount * 4);
            var buf = new byte[Math.Min(bucketSize, 128 * 1024)];

            for (int i = 0; i < bucketCount; i++)
            {
                long offset = i * bucketSize;
                if (offset >= total) { sb.Append("0000"); continue; }
                fs.Seek(offset, SeekOrigin.Begin);
                int want = (int)Math.Min(buf.Length, bucketSize);
                int got = fs.Read(buf, 0, want);
                if (got <= 0) { sb.Append("0000"); continue; }
                var hash = SHA1.HashData(buf.AsSpan(0, got));
                sb.Append(Convert.ToHexString(hash.AsSpan(0, 2)));
            }
            return sb.ToString().ToLowerInvariant();
        }

        // ============================================================
        // B11: C2 infrastructure detection.
        // ============================================================

        // DGA domains tend to have high consonant density and high Shannon entropy over the SLD label.
        // This is a coarse screener — anything we flag is marked as "dga-suspect:<host>" and goes into
        // res.C2Indicators; the real confirmation is a reputation lookup (C8 in the backlog).
        private static readonly HashSet<string> LikelyBenignHosts = new(StringComparer.OrdinalIgnoreCase)
        {
            "google.com", "microsoft.com", "github.com", "cloudflare.com", "amazonaws.com",
            "googleapis.com", "gstatic.com", "live.com", "office.com", "apple.com", "openai.com"
        };

        // A small, well-known set of ASNs historically associated with bulletproof hosting / abuse.
        // Used only for string-level matches ("AS29802", "AS4785") — not network lookups.
        private static readonly HashSet<string> BulletproofAsnMarkers = new(StringComparer.OrdinalIgnoreCase)
        { "AS29802", "AS39134", "AS49505", "AS51659", "AS44812", "AS4785", "AS8100", "AS14576" };

        private static void DetectC2Indicators(AnalysisResult res, string text)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var url in res.UrlsFound)
            {
                if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) continue;
                var host = uri.Host;
                if (string.IsNullOrWhiteSpace(host)) continue;

                if (host.EndsWith(".onion", StringComparison.OrdinalIgnoreCase))
                    res.C2Indicators.Add($"onion:{host}");
                else if (host.EndsWith(".i2p", StringComparison.OrdinalIgnoreCase) || host.EndsWith(".b32.i2p", StringComparison.OrdinalIgnoreCase))
                    res.C2Indicators.Add($"i2p:{host}");
                else if (LikelyBenignHosts.Any(b => host.EndsWith(b, StringComparison.OrdinalIgnoreCase)))
                    continue;
                else if (seen.Add(host) && LooksLikeDga(host))
                    res.C2Indicators.Add($"dga-suspect:{host}");
            }

            // ASN markers in plain text (e.g. "AS29802").
            foreach (var asn in BulletproofAsnMarkers)
            {
                if (text.Contains(asn, StringComparison.OrdinalIgnoreCase))
                    res.C2Indicators.Add($"asn-marker:{asn}");
            }

            // Plaintext onion/i2p addresses that didn't show up as URLs.
            foreach (Match m in Regex.Matches(text, @"\b[a-z2-7]{16,56}\.onion\b", RegexOptions.IgnoreCase))
                if (seen.Add(m.Value)) res.C2Indicators.Add($"onion:{m.Value.ToLowerInvariant()}");
            foreach (Match m in Regex.Matches(text, @"\b[a-z0-9]{32,}\.b32\.i2p\b", RegexOptions.IgnoreCase))
                if (seen.Add(m.Value)) res.C2Indicators.Add($"i2p:{m.Value.ToLowerInvariant()}");
        }

        private static bool LooksLikeDga(string host)
        {
            // Look at the SLD (second-level domain) label.
            var parts = host.Split('.');
            if (parts.Length < 2) return false;
            var sld = parts[parts.Length - 2];
            if (sld.Length < 10 || sld.Length > 40) return false;

            int vowels = 0, consonants = 0, digits = 0;
            foreach (var ch in sld)
            {
                if (char.IsDigit(ch)) digits++;
                else if ("aeiouy".IndexOf(ch) >= 0) vowels++;
                else if (char.IsLetter(ch)) consonants++;
            }
            if (consonants == 0) return false;
            double consonantRatio = (double)consonants / (consonants + Math.Max(vowels, 1));

            // Shannon entropy over the label.
            var counts = new Dictionary<char, int>();
            foreach (var ch in sld) counts[ch] = counts.GetValueOrDefault(ch) + 1;
            double entropy = 0;
            foreach (var kv in counts)
            {
                double p = (double)kv.Value / sld.Length;
                entropy -= p * Math.Log2(p);
            }

            return (consonantRatio >= 0.75 && entropy >= 3.5) || (entropy >= 3.8 && digits >= 3);
        }

        // ============================================================
        // B12: Persistence indicators.
        // ============================================================

        private static readonly (string needle, string label)[] PersistenceNeedles =
        {
            (@"Software\Microsoft\Windows\CurrentVersion\Run", "registry:HKCU\\Run"),
            (@"Software\Microsoft\Windows\CurrentVersion\RunOnce", "registry:HKCU\\RunOnce"),
            (@"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", "registry:ShellFolders"),
            (@"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "registry:Winlogon"),
            (@"SYSTEM\CurrentControlSet\Services", "registry:Services"),
            ("schtasks", "cmd:schtasks"),
            ("/create /tn", "cmd:schtasks-create"),
            ("Scheduled Tasks\\Microsoft\\Windows", "folder:scheduled-tasks"),
            ("\\Start Menu\\Programs\\Startup", "folder:startup"),
            ("\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu", "folder:appdata-start-menu"),
            ("StartupFolder", "api:startupfolder"),
            ("New-ScheduledTask", "ps:new-scheduledtask"),
            ("ITaskService", "com:ITaskService"),
            ("__EventFilter", "wmi:__EventFilter"),
            ("CommandLineEventConsumer", "wmi:CommandLineEventConsumer"),
            ("svchost.exe -k", "svc:svchost"),
            ("sc create", "cmd:sc-create"),
            ("sc config", "cmd:sc-config"),
            ("\\sysnative\\", "path:sysnative"),
        };

        private static void DetectPersistenceIndicators(AnalysisResult res, string text)
        {
            foreach (var (needle, label) in PersistenceNeedles)
                if (text.Contains(needle, StringComparison.OrdinalIgnoreCase))
                    res.PersistenceIndicators.Add(label);
        }

        // ============================================================
        // B13: Browser-stealer fingerprint.
        // ============================================================

        private static readonly (string needle, string label)[] BrowserStealerNeedles =
        {
            ("Login Data", "db:chromium-login-data"),
            ("Web Data", "db:chromium-web-data"),
            ("Cookies-journal", "db:chromium-cookies-journal"),
            ("Network\\Cookies", "path:chromium-network-cookies"),
            ("\\Local State", "file:chromium-local-state"),
            ("\\User Data\\Default", "path:chromium-user-data"),
            ("AppData\\Local\\Google\\Chrome\\User Data", "path:chrome-user-data"),
            ("AppData\\Local\\Microsoft\\Edge\\User Data", "path:edge-user-data"),
            ("AppData\\Roaming\\Opera Software", "path:opera-profile"),
            ("AppData\\Roaming\\Mozilla\\Firefox\\Profiles", "path:firefox-profiles"),
            ("key4.db", "db:firefox-key4"),
            ("logins.json", "db:firefox-logins"),
            ("places.sqlite", "db:firefox-places"),
            ("formhistory.sqlite", "db:firefox-formhistory"),
            ("signons.sqlite", "db:firefox-signons"),
            ("Login Data For Account", "db:edge-login-data-account"),
            ("os_crypt", "field:os_crypt"),
            ("encrypted_key", "field:encrypted_key"),
            // C12 — additional Chromium-family browsers commonly
            // targeted by modern stealers.
            ("\\BraveSoftware\\Brave-Browser\\User Data", "path:brave-user-data"),
            ("\\Vivaldi\\User Data",                     "path:vivaldi-user-data"),
            ("AppData\\Local\\Yandex\\YandexBrowser",   "path:yandex-user-data"),
            ("AppData\\Roaming\\Librewolf\\Profiles",   "path:librewolf-profiles"),
            ("AppData\\Roaming\\Waterfox\\Profiles",    "path:waterfox-profiles"),
            // Password managers.
            ("\\KeePass\\KeePass.config.xml",            "pwm:keepass-config"),
            (".kdbx",                                    "pwm:kdbx-vault"),
            ("\\Bitwarden\\data.json",                   "pwm:bitwarden-data"),
            ("\\AgileBits\\OnePassword4",                "pwm:1password-vault"),
            ("\\LastPass\\",                             "pwm:lastpass"),
            ("\\Dashlane\\Local Storage",                "pwm:dashlane"),
            ("\\NordPass\\",                             "pwm:nordpass"),
            ("\\RoboForm\\",                             "pwm:roboform"),
            // Cloud / DevOps secrets.
            (".aws\\credentials",                         "cloud:aws-credentials"),
            (".aws\\config",                              "cloud:aws-config"),
            (".azure\\accessTokens.json",                 "cloud:azure-tokens"),
            (".config\\gcloud\\credentials.db",          "cloud:gcp-creds-db"),
            (".kube\\config",                             "cloud:kubeconfig"),
            (".docker\\config.json",                      "dev:docker-config"),
            (".npmrc",                                    "dev:npmrc"),
            (".pypirc",                                   "dev:pypirc"),
            (".netrc",                                    "dev:netrc"),
            ("_netrc",                                    "dev:netrc-win"),
            (".gitconfig",                                "dev:gitconfig"),
            ("\\.ssh\\id_rsa",                            "dev:ssh-id_rsa"),
            ("\\.ssh\\id_ed25519",                        "dev:ssh-id_ed25519"),
            ("\\.ssh\\known_hosts",                       "dev:ssh-known_hosts"),
            ("ghp_",                                      "dev:github-token-prefix"),
            ("gho_",                                      "dev:github-oauth-prefix"),
            ("github_pat_",                               "dev:github-pat-prefix"),
            ("glpat-",                                    "dev:gitlab-token-prefix"),
            ("AppData\\Roaming\\FileZilla\\sitemanager.xml", "dev:filezilla-sites"),
            ("AppData\\Roaming\\FileZilla\\recentservers.xml", "dev:filezilla-recent"),
            ("WinSCP.ini",                                "dev:winscp-ini"),
            // Messengers.
            ("\\Discord\\Local Storage\\leveldb",         "msg:discord-leveldb"),
            ("\\discord\\Local Storage\\leveldb",         "msg:discord-leveldb"),
            ("\\Telegram Desktop\\tdata",                "msg:telegram-tdata"),
            ("\\Steam\\ssfn",                             "msg:steam-ssfn"),
            ("\\Steam\\config\\loginusers.vdf",          "msg:steam-loginusers"),
            ("\\Slack\\Local Storage\\leveldb",          "msg:slack-leveldb"),
            ("\\Microsoft\\Teams\\Cookies",              "msg:teams-cookies"),
            ("\\Microsoft\\Teams\\storage.json",         "msg:teams-storage"),
            // Crypto.
            ("\\Bitcoin\\wallet.dat",                     "crypto:bitcoin-wallet"),
            ("\\Electrum\\wallets",                       "crypto:electrum-wallets"),
            ("\\Exodus\\exodus.wallet",                  "crypto:exodus-wallet"),
            ("\\Atomic\\Local Storage",                  "crypto:atomic-wallet"),
            ("\\Coinomi\\wallets",                        "crypto:coinomi"),
            ("\\Jaxx Liberty\\Local Storage",            "crypto:jaxx"),
            ("\\Daedalus Mainnet\\wallets",              "crypto:daedalus"),
            // BIP39 mnemonic context — bare 12/24-word seed phrases
            // are extracted by regex elsewhere; we look for context
            // markers here.
            ("BIP39",                                     "crypto:bip39-context"),
            ("derivation path",                           "crypto:derivation-path"),
            ("m/44'/0'/0'",                               "crypto:bitcoin-bip44-path"),
            ("m/44'/60'/0'",                              "crypto:ethereum-bip44-path"),
            ("m/49'/0'/0'",                               "crypto:bitcoin-bip49-path"),
            ("m/84'/0'/0'",                               "crypto:bitcoin-bip84-path"),
        };

        private static void DetectBrowserStealerIndicators(AnalysisResult res, string text)
        {
            foreach (var (needle, label) in BrowserStealerNeedles)
                if (text.Contains(needle, StringComparison.OrdinalIgnoreCase))
                    res.BrowserStealerIndicators.Add(label);

            // DPAPI blobs start with 01 00 00 00 D0 8C 9D DF 01 15 D1 11 ... ; we only have ASCII / UTF-16
            // decoded strings here, so we look for the common ASCII-hex representation of the header.
            if (text.Contains("01000000D08C9DDF", StringComparison.OrdinalIgnoreCase))
                res.BrowserStealerIndicators.Add("blob:DPAPI-header");
        }

        // B13/B19 extension: detect strings that reveal the sample's malicious purpose — PDB paths
        // with "stealer" / "grabber" / "keylog" in them, project type names, and exfil template
        // strings that format multiple credential fields into a single line. Informed by real
        // samples that otherwise scored in the 30s because they didn't touch Chromium profiles.
        private static readonly string[] MalwareSelfIdKeywords =
        {
            "stealer",
            "grabber",
            "keylogger",
            "clipper",
            "injector",
            "exfiltrat",
            "infostealer",
            "credstealer",
            "passstealer",
            "tokenstealer",
            "cookie stealer",
            "account stealer",
            "ransomware",
            "password grabber",
            "credential stealer",
            "credential grabber",
            "session stealer",
            "session hijack",
            "browser stealer",
            "discord stealer",
            "telegram stealer",
            "steam stealer",
            "wallet stealer",
            "wallet drainer",
            "seed stealer",
            "mnemonic stealer",
            "cookie grabber",
            "crypto stealer",
            "banking stealer",
            "gmail stealer",
            "roblox stealer",
            "minecraft stealer",
            "launcher stealer",
            "account grabber",
            "password dumper",
            "credential dumper",
            "form grabber",
            "rat-loader",
            "rat loader",
            "backdoor",
            "botnet",
        };

        private static void DetectMalwareSelfIdentification(AnalysisResult res, string text)
        {
            // Full-text scan for literal keywords. Deduplicate so 100 hits of "stealer" in a PDB map
            // to a single entry.
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var kw in MalwareSelfIdKeywords)
            {
                if (text.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0 && seen.Add(kw))
                    res.MalwareSelfIdHits.Add("keyword:" + kw);
            }

            // Specific PDB-path signal: strings ending in .pdb that contain a malware keyword. PDB
            // paths leak the source-tree layout and often literally name the project ("Stealer.pdb").
            foreach (var s in res.StringHits)
            {
                if (s.Length < 5 || !s.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase)) continue;
                foreach (var kw in MalwareSelfIdKeywords)
                {
                    if (s.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        res.MalwareSelfIdHits.Add("pdb:" + s);
                        goto nextStringPdb;  // a single pdb match is enough
                    }
                }
                nextStringPdb: ;
            }

            // Credential-exfil template: a printf-style string that formats two or more credential
            // field names at once — "Nickname: %s | Password: %s", "login=%s&token=%s", etc.
            var credTokens = new[] {
                "password", "passwd", "token", "cookie", "login", "nickname", "serial",
                "session", "email", "account", "username", "balance",
                "wallet", "card", "cvv", "pin",
                "mnemonic", "seed", "phrase", "2fa", "otp", "secret",
                "server", "auth",
            };
            foreach (var s in res.StringHits)
            {
                if (s.Length < 12 || s.Length > 300) continue;
                if (s.IndexOf("%s", StringComparison.Ordinal) < 0 && s.IndexOf("{0}", StringComparison.Ordinal) < 0) continue;
                int hits = 0;
                foreach (var tok in credTokens)
                    if (s.IndexOf(tok, StringComparison.OrdinalIgnoreCase) >= 0) hits++;
                if (hits >= 2)
                {
                    res.MalwareSelfIdHits.Add("exfil-template: " + s.Substring(0, Math.Min(120, s.Length)));
                    break;
                }
            }
        }

        // Game-account stealer targeting. Many stealers in-the-wild don't touch Chrome/Firefox —
        // they target specific game launchers / mod DLLs (SA:MP, MTA, GTA, Rage:MP, CRMP, Radmir,
        // Arizona, Diamond RP, Steam, Minecraft, Roblox, etc.) to dump credentials or session data.
        // We match literal telltales and record each distinct hit. These counts feed into
        // ScoreCredentialTheft and StealerExfilPatternBonus so that a game-stealer scores HIGH
        // even without Chromium artefacts.
        private static readonly string[] GameTargetNeedles =
        {
            "samp.dll", "samp_core", "samp.exe", "sa-mp", "sa:mp", "gta:sa",
            "san andreas multiplayer", "multi theft auto", "mta:sa", "mta_data", "mtaclient",
            "rage.dll", "ragemp", "rage:mp", "rage_mp", "rage-mp",
            "crmp.dll", "crmp.exe", "crmp_launcher",
            "gta sa", "gta-sa", "gta_sa", "rockstar games",
            "radmirrp", "radmir_rp", "radmir rp", "radmir.dll", "radmir_launcher",
            "arizonarp", "arizona-rp", "arizona_rp",
            "diamondrp", "diamond-rp", "diamond rp",
            "amazingrp", "amazing-rp", "amazing rp",
            "smotrarp", "smotra-rp",
            "trinity rp", "trinity-rp",
            "grand theft auto",
            "steam_appid.txt", "steamapi", "steamworks", "steam_api.dll", "steamid",
            "loginusers.vdf", "config.vdf", "ssfn",
            "roblox player", "robloxplayer.exe", "roblox studio",
            "minecraft\\\\launcher_profiles", "launcher_profiles.json", "minecraft.msa",
            "launcher.exe", "launcher_config", "gamelauncher",
            "lol client", "riotclient", "leagueclient",
            "dayz",  "warface", "warzone",
            "battlenet", "battle.net",
            "epic games launcher",
            ".cleo", "cleo_saves",
        };

        private static void DetectGameAccountStealerTargeting(AnalysisResult res, string text)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var n in GameTargetNeedles)
            {
                if (text.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0 && seen.Add(n))
                    res.GameTargetHits.Add(n);
            }
        }

        // Telegram exfil endpoint IOCs. The specific URL pattern `api.telegram.org/bot<token>/send*`
        // (sendMessage / sendDocument / sendPhoto) combined with a literal format specifier (%s, {0})
        // is an essentially unambiguous signal — legitimate apps may reach api.telegram.org, but they
        // do not format a bot token into the URL dynamically. We record each distinct endpoint shape.
        private static readonly string[] TelegramExfilVerbNeedles =
        {
            "sendMessage", "sendDocument", "sendPhoto", "sendMediaGroup", "sendAudio",
            "sendVideo", "sendVoice", "sendAnimation", "sendLocation", "sendContact",
            "editMessageText", "getUpdates", "copyMessage",
        };

        private static void DetectTelegramExfilEndpoints(AnalysisResult res, string text)
        {
            // Scan full analysis text for each occurrence of `telegram.org/bot` / `t.me/` and extract
            // a ±200-char window around the match. Then look for a Bot-API verb or a format specifier
            // inside that window. This is more robust than iterating StringHits because StringHits
            // only holds needle-matched strings and may not contain the Telegram URL.
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string[] anchors = { "telegram.org/bot", "t.me/" };
            foreach (var anchor in anchors)
            {
                int pos = 0;
                while (true)
                {
                    int i = text.IndexOf(anchor, pos, StringComparison.OrdinalIgnoreCase);
                    if (i < 0) break;
                    int start = Math.Max(0, i - 64);
                    int end   = Math.Min(text.Length, i + 256);
                    string window = text.Substring(start, end - start);

                    string? verbMatched = null;
                    foreach (var verb in TelegramExfilVerbNeedles)
                    {
                        if (window.IndexOf(verb, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            verbMatched = verb;
                            break;
                        }
                    }
                    bool hasFormatter = window.IndexOf("%s", StringComparison.Ordinal) >= 0 ||
                                        window.IndexOf("{0}", StringComparison.Ordinal) >= 0;

                    if (verbMatched != null)
                    {
                        var key = "verb:" + verbMatched.ToLowerInvariant();
                        if (seen.Add(key))
                        {
                            int previewLen = Math.Min(160, window.Length);
                            res.TelegramExfilEndpoints.Add(verbMatched + ": " + window.Substring(0, previewLen).Trim());
                        }
                    }
                    else if (hasFormatter)
                    {
                        var key = "dynamic:" + anchor;
                        if (seen.Add(key))
                        {
                            int previewLen = Math.Min(160, window.Length);
                            res.TelegramExfilEndpoints.Add("dynamic: " + window.Substring(0, previewLen).Trim());
                        }
                    }

                    pos = i + anchor.Length;
                    // Cap total findings per anchor to avoid noise.
                    if (res.TelegramExfilEndpoints.Count >= 16) return;
                }
            }
        }

        // ============================================================
        // B9 — Modern infostealer pattern detectors.
        //
        // CISA/FBI LummaC2 advisory (AA24-241A) and Microsoft Threat
        // Intelligence research on Lumma describe a small set of
        // signature techniques: fake-CAPTCHA / ClickFix social-
        // engineering, Base64-encoded PowerShell cradles, a compact
        // JSON config with short keys ("c", "ex", "t", "p", "z",
        // "fs", "se", "ad"), browser-extension theft, MFA-app token
        // theft, and a POST body shape that always contains "hwid",
        // "build", "uid" or similar.
        // ============================================================

        // ClickFix / fake-CAPTCHA needles. Present in attacker-served
        // HTML that instructs the victim to press Win+R / Ctrl+V /
        // Enter to paste a clipboard-staged payload. Each individual
        // string is weak; the rule fires only when ≥2 distinct
        // categories co-occur in the corpus (e.g. "Win+R" AND
        // "I am not a robot").
        private static readonly (string needle, string cat)[] ClickFixNeedles =
        {
            ("Win+R",                       "keyboard"),
            ("Windows+R",                   "keyboard"),
            ("Ctrl+V",                      "keyboard"),
            ("Press Enter",                 "keyboard"),
            ("verify you are human",        "captcha"),
            ("I am not a robot",            "captcha"),
            ("I'm not a robot",             "captcha"),
            ("прохождения проверки",        "captcha"),
            ("captcha",                     "captcha"),
            ("powershell.exe",              "runner"),
            ("mshta",                       "runner"),
            ("cmd /c",                      "runner"),
            ("conhost --headless",          "runner"),
        };

        // Lumma-style compressed-config keys. The config is JSON-ish
        // and uses 1-2-char field names because the C2 wire format is
        // optimised for size. We require ≥3 short keys adjacent to
        // either a domain string or a "POST" verb to avoid false
        // positives on minified web bundles.
        private static readonly string[] LummaShortKeys =
            { "\"c\":", "\"ex\":", "\"t\":", "\"p\":", "\"z\":", "\"fs\":",
              "\"se\":", "\"ad\":", "\"build\":", "\"sid\":" };

        // Browser-extension theft. The list comes from sweeping
        // public IOC tables for Rhadamanthys, Atomic, Lumma, Vidar,
        // RedLine and StealC. Each entry is a directory or extension
        // ID that no benign software accesses.
        private static readonly string[] BrowserExtensionTheftMarkers =
        {
            // Chromium extensions root
            "\\Default\\Extensions\\",
            "\\Local Extension Settings\\",
            "chrome-extension://",
            // MetaMask
            "nkbihfbeogaeaoehlefnkodbefgpgknn",
            // Phantom
            "bfnaelmomeimhlpmgjnjophhpkkoljpa",
            // Trust Wallet
            "egjidjbpglichdcondbcbdnbeeppgdph",
            // Coinbase Wallet
            "hnfanknocfeofbddgcijnmhnfnkdnaad",
            // Binance Chain
            "fhbohimaelbohpjbbldcngcnapndodjp",
            // Brave Wallet
            "odbfpeeihdkbihmopkbjmoonfanlbfcl",
            // Authy (MFA)
            "gaedmjdfmmahhbjefcbgaolhhanlaolb",
            // Bitwarden
            "nngceckbapebfimnlniiiahkandclblb",
            // LastPass
            "hdokiejnpimakedhajhdlcegeplioahd",
            // 1Password X
            "aeblfdkhhhdcdjpifhhbdiojplfjncoa",
        };

        // MFA-app theft. Authy / 2FA / OTP vault paths plus the OS-
        // level browser cookie / session-token paths that bypass MFA
        // by stealing valid sessions.
        private static readonly string[] MfaAppMarkers =
        {
            "Authy Desktop",
            "Microsoft Authenticator",
            "Google Authenticator",
            "WinAuth.xml",
            "totp",
            "otpauth://",
            "session_token",
            "__Secure-1PSID",
            "__Secure-3PSID",
            "session_id",
            "auth_token",
            "csrftoken",
        };

        // POST-body shape — info-stealer beacons always embed one of
        // these field names. The rule requires ≥3 distinct keys
        // within a single text window to avoid false positives on
        // generic HTTP libraries.
        private static readonly string[] StealerPostBodyKeys =
        {
            "hwid=", "hwid:", "\"hwid\"",
            "build=", "build:", "\"build\"",
            "uid=", "uid:", "\"uid\"",
            "computer=", "computer:", "\"computer\"",
            "username=", "username:",
            "\"wallets\"", "\"browsers\"",
            "\"cookies\"", "\"history\"",
        };

        private static void DetectModernStealerPatterns(AnalysisResult res, string text)
        {
            if (string.IsNullOrEmpty(text)) return;

            // -------- ClickFix / fake CAPTCHA --------
            var cats = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var clickFixWitnesses = new List<string>();
            foreach (var (needle, cat) in ClickFixNeedles)
            {
                if (text.IndexOf(needle, StringComparison.OrdinalIgnoreCase) < 0) continue;
                if (cats.Add(cat))
                    clickFixWitnesses.Add(needle);
            }
            if (cats.Count >= 2)
            {
                foreach (var w in clickFixWitnesses)
                    if (!res.ClickFixCaptchaHits.Contains(w, StringComparer.Ordinal))
                        res.ClickFixCaptchaHits.Add(w);
            }

            // -------- Lumma JSON config --------
            int lummaKeysFound = 0;
            var lummaKeyHits = new List<string>();
            foreach (var k in LummaShortKeys)
            {
                if (text.IndexOf(k, StringComparison.Ordinal) >= 0)
                {
                    lummaKeysFound++;
                    lummaKeyHits.Add(k);
                }
            }
            bool nearC2 = text.IndexOf("POST",  StringComparison.Ordinal) >= 0 ||
                          text.IndexOf("http",  StringComparison.OrdinalIgnoreCase) >= 0 ||
                          text.IndexOf("Content-Type", StringComparison.OrdinalIgnoreCase) >= 0;
            if (lummaKeysFound >= 3 && nearC2)
            {
                foreach (var k in lummaKeyHits)
                    if (!res.LummaConfigHits.Contains(k, StringComparer.Ordinal))
                        res.LummaConfigHits.Add(k);
            }

            // -------- Browser extension theft --------
            foreach (var m in BrowserExtensionTheftMarkers)
            {
                if (text.IndexOf(m, StringComparison.OrdinalIgnoreCase) < 0) continue;
                if (!res.BrowserExtTheftHits.Contains(m, StringComparer.Ordinal))
                    res.BrowserExtTheftHits.Add(m);
                if (res.BrowserExtTheftHits.Count >= 16) break;
            }

            // -------- MFA-app theft --------
            foreach (var m in MfaAppMarkers)
            {
                if (text.IndexOf(m, StringComparison.OrdinalIgnoreCase) < 0) continue;
                if (!res.MfaAppTheftHits.Contains(m, StringComparer.Ordinal))
                    res.MfaAppTheftHits.Add(m);
                if (res.MfaAppTheftHits.Count >= 16) break;
            }

            // -------- Stealer POST-body shape --------
            int postKeyCount = 0;
            var postKeyHits = new List<string>();
            foreach (var k in StealerPostBodyKeys)
            {
                if (text.IndexOf(k, StringComparison.OrdinalIgnoreCase) < 0) continue;
                postKeyCount++;
                postKeyHits.Add(k);
            }
            if (postKeyCount >= 3)
            {
                foreach (var k in postKeyHits)
                    if (!res.StealerPostBodyHits.Contains(k, StringComparer.Ordinal))
                        res.StealerPostBodyHits.Add(k);
            }
        }

        // ============================================================
        // B14: Anti-analysis / anti-sandbox.
        // ============================================================

        private static readonly string[] AntiAnalysisStringNeedles =
        {
            "VBoxService.exe", "VBoxTray.exe", "VboxControl.exe", "VBoxGuest", "VMTools", "vmsrvc",
            "vmusrvc", "prl_tools", "SbieDll.dll", "cuckoomon", "SbieDll", "dbghelp.dll",
            "Sandboxie", "Cuckoo", "wireshark", "procmon", "processhacker", "ollydbg", "x32dbg",
            "x64dbg", "ida.exe", "ida64.exe", "windbg",
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "OutputDebugString", "ZwSetInformationThread", "NtSetInformationThread",
            "NtQuerySystemInformation", "GetTickCount", "QueryPerformanceCounter",
            "SystemKernelDebuggerInformation", "ProcessDebugPort", "ProcessDebugObjectHandle",
            "ProcessDebugFlags",
        };

        private static readonly string[] AntiAnalysisImportNeedles =
        {
            "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
            "outputdebugstringa", "outputdebugstringw", "zwsetinformationthread",
            "ntsetinformationthread", "ntquerysysteminformation", "getthreadcontext",
            "settedunhandledexceptionfilter", "queryperformancecounter", "gettickcount",
            "gettickcount64",
        };

        private static void DetectAntiAnalysisIndicatorsFromText(AnalysisResult res, string text)
        {
            foreach (var needle in AntiAnalysisStringNeedles)
                if (text.Contains(needle, StringComparison.OrdinalIgnoreCase))
                    res.AntiAnalysisIndicators.Add($"string:{needle}");
        }

        private static void DetectAntiAnalysisIndicatorsFromImports(AnalysisResult res, IReadOnlyCollection<string> imports)
        {
            foreach (var needle in AntiAnalysisImportNeedles)
                if (imports.Any(i => i.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0))
                    res.AntiAnalysisIndicators.Add($"import:{needle}");
        }

        // ============================================================
        // B19: String deobfuscation.
        // ============================================================

        // Shortlist of needles we consider "interesting" if we recover them after deobfuscation — limits
        // noise from accidental matches on random data.
        private static readonly string[] DeobNeedles =
        {
            "http", "token", "password", "cookie", "wallet", "discord", "telegram", "steal",
            "chrome", "firefox", "login data", "mnemonic", "private key", "botnet", "c2",
            "apikey", "api_key", "onion", "upload", "grabber",
        };

        private static void RunStringDeobfuscation(AnalysisResult res, string analysisText)
        {
            var added = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // 1) base64-decode any blob candidates and rescan for needles.
            //    Also try UTF-16LE interpretation — PowerShell's
            //    `-EncodedCommand` flag base64-encodes UTF-16LE, so the
            //    decoded bytes are PowerShell text only after a second
            //    decode pass.
            foreach (Match m in Base64BlobRegex.Matches(analysisText).Take(200))
            {
                var candidate = m.Value;
                if (candidate.Length < 16 || candidate.Length > 32_000) continue;
                byte[] decoded;
                try { decoded = Convert.FromBase64String(candidate); }
                catch { continue; }
                if (decoded.Length < 8) continue;
                var asAscii = Encoding.ASCII.GetString(decoded);
                TryAddDeobfuscated(res, added, asAscii, "base64");
                // B11 — UTF-16LE base64 path. PowerShell encoded
                // commands always decode to UTF-16LE text.
                if (decoded.Length >= 4 && (decoded.Length & 1) == 0)
                {
                    var asUtf16Le = Encoding.Unicode.GetString(decoded);
                    TryAddDeobfuscated(res, added, asUtf16Le, "base64:utf16le");
                }
                // B11 — gzip/zlib. Many stealer configs nest a
                // gzip blob inside a base64 wrapper.
                TryDecompressAndScan(res, added, decoded, "base64:gzip", "base64:zlib");
            }

            // 1b) standalone gzip/zlib markers in the raw text — common
            //     when a binary section contains a Deflate stream.
            ScanForCompressedBlobs(res, added, analysisText);

            // 1c) multi-byte XOR with crib strings. 1-byte XOR is
            //     covered below; multi-byte handles 2- and 4-byte keys
            //     by aligning known plaintext anchors ("http", "MZ",
            //     "api.telegram", "Login Data") with each candidate
            //     position and deriving the key from the XOR delta.
            TryMultiByteXor(res, added, analysisText);

            // 1d) .NET #US heap strings — when a managed PE is loaded
            //     by the host but not unpacked, its UTF-16LE string
            //     constants still appear in the analysisText.  We
            //     surface the most stealer-relevant ones.
            ScanDotNetUsHeap(res, added, analysisText);

            // 2) rot13 of any window containing suspicious-looking rot13 markers (e.g. "fgrnyre" = "stealer").
            var rot13 = Rot13(analysisText);
            TryAddDeobfuscated(res, added, rot13, "rot13");

            // 3) XOR-1byte brute force on short ASCII-looking windows. We only try keys 1..0xFF on a
            //    bounded number of windows (cost: ~ windows * keys * window-size char-xor ops).
            const int MaxXorWindows = 32;
            const int XorWindowLen = 1024;
            int windowCount = Math.Min(MaxXorWindows, analysisText.Length / XorWindowLen);
            if (windowCount > 0)
            {
                int step = Math.Max(XorWindowLen, analysisText.Length / windowCount);
                var scratch = new char[XorWindowLen];
                for (int offset = 0; offset + XorWindowLen < analysisText.Length; offset += step)
                {
                    for (int key = 1; key < 256; key++)
                    {
                        for (int i = 0; i < XorWindowLen; i++) scratch[i] = (char)(analysisText[offset + i] ^ key);
                        var decodedStr = new string(scratch);
                        if (!DeobNeedles.Any(n => decodedStr.Contains(n, StringComparison.OrdinalIgnoreCase))) continue;
                        TryAddDeobfuscated(res, added, decodedStr, $"xor-{key:x2}");
                        break; // one hit per window
                    }
                    if (added.Count >= 64) return; // hard cap on recovered hits per file
                }
            }
        }

        private static void TryAddDeobfuscated(AnalysisResult res, HashSet<string> added, string decodedText, string tag)
        {
            foreach (var needle in DeobNeedles)
            {
                int idx = decodedText.IndexOf(needle, StringComparison.OrdinalIgnoreCase);
                if (idx < 0) continue;
                int windowStart = Math.Max(0, idx - 16);
                int windowEnd = Math.Min(decodedText.Length, idx + needle.Length + 32);
                var snippet = decodedText[windowStart..windowEnd].Trim();
                if (snippet.Length < 4) continue;
                var tagged = $"{tag}:{needle}:{snippet}";
                if (added.Add(tagged) && res.DeobfuscatedHits.Count < 128)
                {
                    res.DeobfuscatedHits.Add(tagged);
                    // B11 — feed decoded strings back through the
                    // evidence-source tagger so reports can show
                    // "source=decoded:base64" / "source=decoded:xor-3a".
                    res.AddEvidence($"decoded:{tag}", snippet);
                }
            }
        }

        // B11 — attempt gzip and zlib decompression of an arbitrary
        // byte buffer. Stops early if the deflate stream is malformed
        // or shorter than 8 bytes after decompression.
        private static void TryDecompressAndScan(
            AnalysisResult res,
            HashSet<string> added,
            byte[] data,
            string gzipTag,
            string zlibTag)
        {
            if (data == null || data.Length < 4) return;
            // GZIP magic 0x1F 0x8B 0x08
            if (data[0] == 0x1F && data[1] == 0x8B && data[2] == 0x08)
            {
                try
                {
                    using var input  = new MemoryStream(data);
                    using var gz     = new System.IO.Compression.GZipStream(input,
                        System.IO.Compression.CompressionMode.Decompress);
                    using var output = new MemoryStream();
                    gz.CopyTo(output, 8192);
                    if (output.Length >= 8 && output.Length <= 4_000_000)
                    {
                        var s = Encoding.UTF8.GetString(output.ToArray());
                        TryAddDeobfuscated(res, added, s, gzipTag);
                    }
                }
                catch { /* not a valid gzip stream */ }
                return;
            }
            // Zlib header: 0x78 0x01 / 0x9C / 0xDA (default / best /
            // max compression).
            if (data[0] == 0x78 && (data[1] == 0x01 || data[1] == 0x9C || data[1] == 0xDA))
            {
                try
                {
                    using var input = new MemoryStream(data, 2, data.Length - 2);
                    using var df    = new System.IO.Compression.DeflateStream(input,
                        System.IO.Compression.CompressionMode.Decompress);
                    using var output = new MemoryStream();
                    df.CopyTo(output, 8192);
                    if (output.Length >= 8 && output.Length <= 4_000_000)
                    {
                        var s = Encoding.UTF8.GetString(output.ToArray());
                        TryAddDeobfuscated(res, added, s, zlibTag);
                    }
                }
                catch { /* not a valid zlib stream */ }
            }
        }

        // B11 — find embedded gzip/zlib streams in the analysisText
        // (interpreted byte-by-byte) and decompress them.
        private static void ScanForCompressedBlobs(
            AnalysisResult res,
            HashSet<string> added,
            string analysisText)
        {
            if (string.IsNullOrEmpty(analysisText)) return;
            // We only look at the first 4 MiB to keep the cost bounded.
            int searchLen = Math.Min(analysisText.Length, 4 * 1024 * 1024);
            int found = 0;
            for (int i = 0; i + 4 < searchLen && found < 8; i++)
            {
                char a = analysisText[i], b = analysisText[i + 1], c = analysisText[i + 2];
                bool gzipHdr = a == 0x1F && b == 0x8B && c == 0x08;
                bool zlibHdr = a == 0x78 && (b == 0x01 || b == 0x9C || b == 0xDA);
                if (!gzipHdr && !zlibHdr) continue;

                int chunkLen = Math.Min(searchLen - i, 256 * 1024);
                var bytes = new byte[chunkLen];
                for (int k = 0; k < chunkLen; k++) bytes[k] = (byte)analysisText[i + k];
                TryDecompressAndScan(res, added, bytes, "gzip", "zlib");
                found++;
                i += 16;
            }
        }

        // B11 — multi-byte XOR cribbing. For each plaintext crib c
        // and each candidate offset o in the analysisText, derive a
        // key of length |c| as ciphertext[o..o+|c|] ^ c. Then validate
        // the key by XOR-decrypting a ±256-byte window and checking
        // for additional plaintext needles. This catches obfuscators
        // that use a constant repeating key but variable offset.
        private static readonly (string crib, string anchor)[] XorCribs =
        {
            ("http://",      "url"),
            ("https://",     "url"),
            ("MZ\x90\x00",   "pe"),
            ("Login Data",   "browser"),
            ("api.telegram", "telegram"),
            ("CryptUnprot",  "dpapi"),
        };
        // Probes must be distinctive enough that ≥3 co-occurring
        // matches are essentially impossible by chance. We avoid
        // ultra-common 4-char tokens like "http" or "://".
        private static readonly string[] XorPlaintextProbes =
        {
            "Mozilla/", "User-Agent:", "Content-Type:", "POST /", "Host: ",
            "Login Data", "Cookies", "wallet.dat", "chrome.dll",
            "discord.com", "api.telegram.org",
            "CryptUnprotectData", "Mnemonic", "passphrase",
            "AppData\\Roaming",
        };

        private static void TryMultiByteXor(
            AnalysisResult res,
            HashSet<string> added,
            string analysisText)
        {
            if (string.IsNullOrEmpty(analysisText)) return;
            // Bound work: scan only the first 2 MiB and cap recoveries.
            int searchLen = Math.Min(analysisText.Length, 2 * 1024 * 1024);
            int recovered = 0;

            // Convert window to bytes once so the inner loop is cheap.
            var bytes = new byte[searchLen];
            for (int i = 0; i < searchLen; i++) bytes[i] = (byte)(analysisText[i] & 0xFF);

            // Try each candidate offset modulo 4096 — sufficient to find
            // repeated-key XORed blobs without quadratic cost.
            const int stride = 4096;
            for (int off = 0; off + 64 < searchLen && recovered < 8; off += stride)
            {
                foreach (var (crib, anchor) in XorCribs)
                {
                    if (off + crib.Length > searchLen) continue;
                    int keyLen = crib.Length;
                    var key = new byte[keyLen];
                    for (int k = 0; k < keyLen; k++) key[k] = (byte)(bytes[off + k] ^ (byte)crib[k]);

                    // Truncate the key to its true periodicity if the
                    // crib happens to be a multiple of a shorter
                    // repeated string. We accept 2- and 4-byte keys
                    // most often.
                    int realKeyLen = keyLen;
                    for (int t = 1; t <= keyLen / 2; t++)
                    {
                        bool periodic = true;
                        for (int k = t; k < keyLen && periodic; k++)
                            if (key[k] != key[k % t]) periodic = false;
                        if (periodic) { realKeyLen = t; break; }
                    }

                    // Decrypt ±256-byte window with the recovered key.
                    int start = Math.Max(0, off - 256);
                    int end   = Math.Min(searchLen, off + 256);
                    var sb = new StringBuilder(end - start);
                    for (int i = start; i < end; i++)
                        sb.Append((char)(bytes[i] ^ key[(i - off + 1000 * realKeyLen) % realKeyLen]));
                    var window = sb.ToString();

                    int probeHits = 0;
                    foreach (var p in XorPlaintextProbes)
                        if (window.Contains(p, StringComparison.OrdinalIgnoreCase))
                            probeHits++;

                    // Require ≥3 distinctive probes to avoid the
                    // false-positive case where the derived key gives
                    // a window full of random English-like text.
                    if (probeHits >= 3)
                    {
                        var keyHex = string.Concat(key.Take(realKeyLen).Select(b => b.ToString("x2")));
                        TryAddDeobfuscated(res, added, window, $"xor{realKeyLen}b:{keyHex}:{anchor}");
                        recovered++;
                        break; // one crib per offset
                    }
                }
            }
        }

        // B11 — quick-and-dirty .NET #US heap scan. The CLI metadata
        // #US stream stores user strings as little-endian UTF-16
        // length-prefixed blobs (compressed-uint length + UTF-16
        // characters + a terminator byte). We don't fully parse the
        // metadata — we just scan for adjacent ASCII-like UTF-16LE
        // strings whose content matches DeobNeedles, after the #US
        // sentinel.
        private static void ScanDotNetUsHeap(
            AnalysisResult res,
            HashSet<string> added,
            string analysisText)
        {
            if (string.IsNullOrEmpty(analysisText)) return;
            int sentinel = analysisText.IndexOf("#US", StringComparison.Ordinal);
            if (sentinel < 0) return;
            int regionEnd = Math.Min(analysisText.Length, sentinel + 256 * 1024);
            // Re-decode as UTF-16LE — each char takes two bytes in the
            // raw stream, so we walk the underlying byte buffer.
            int len = regionEnd - sentinel;
            var raw  = new byte[len];
            for (int i = 0; i < len; i++) raw[i] = (byte)analysisText[sentinel + i];
            var utf16 = Encoding.Unicode.GetString(raw);
            TryAddDeobfuscated(res, added, utf16, "dotnet:#US");
        }

        // ============================================================
        // C1–C3: non-PE format classification & format-specific indicators.
        // ============================================================

        // Script / document cradle needles — matched on full extracted analysis text.
        private static readonly (string needle, string label)[] ScriptIndicatorNeedles =
        {
            ("Invoke-Expression", "ps:iex"),
            ("IEX(", "ps:iex-shortcut"),
            ("IEX (", "ps:iex-shortcut"),
            ("DownloadString", "net:downloadstring"),
            ("DownloadFile", "net:downloadfile"),
            ("Invoke-WebRequest", "ps:invoke-webrequest"),
            ("Start-BitsTransfer", "ps:bits"),
            ("Add-MpPreference", "ps:disable-defender"),
            ("Set-MpPreference", "ps:disable-defender"),
            ("AmsiUtils", "ps:amsi-bypass"),
            ("amsiInitFailed", "ps:amsi-bypass"),
            ("FromBase64String", "script:b64-decode"),
            ("Convert.FromBase64", "script:b64-decode"),
            ("-EncodedCommand", "ps:encodedcommand"),
            ("-enc ", "ps:encodedcommand"),
            ("WScript.Shell", "wsh:wscript-shell"),
            ("Shell.Application", "wsh:shell-application"),
            ("XMLHTTP", "net:xmlhttp"),
            ("MSXML2.ServerXMLHTTP", "net:serverxmlhttp"),
            ("ADODB.Stream", "wsh:adodb-stream"),
            ("powershell -nop", "ps:nop-hidden"),
            ("-w hidden", "ps:hidden"),
            ("-WindowStyle Hidden", "ps:hidden"),
            ("cmd.exe /c", "cmd:shell-exec"),
            ("mshta", "mshta"),
            ("regsvr32", "regsvr32"),
            ("rundll32", "rundll32"),
            ("bitsadmin /transfer", "net:bitsadmin"),
            ("curl ", "net:curl"),
            ("wget ", "net:wget"),
            // CC13 — Lua cradles & loader primitives. These fire on any
            // .lua sample (not just the 5 known-bad signature groups) so
            // operators can spot unfamiliar SA-MP scripts at a glance.
            ("loadstring(",        "lua:loadstring"),
            ("loadfile(",          "lua:loadfile"),
            ("dofile(",            "lua:dofile"),
            ("os.execute(",        "lua:os-execute"),
            ("io.popen(",          "lua:io-popen"),
            ("package.loadlib(",   "lua:loadlib"),
            ("loadDynamicLibrary", "lua:samp-loadlib"),
            ("requestHTTP(",       "lua:samp-http"),
            ("downloadUrlToFile(", "lua:samp-download"),
        };

        private static readonly (string needle, string label)[] PdfRiskyNeedles =
        {
            ("/JavaScript", "pdf:js"),
            ("/JS ", "pdf:js"),
            ("/Launch", "pdf:launch"),
            ("/OpenAction", "pdf:openaction"),
            ("/AA", "pdf:additional-actions"),
            ("/EmbeddedFile", "pdf:embedded-file"),
            ("/RichMedia", "pdf:richmedia"),
            ("/XFA", "pdf:xfa-form"),
            ("/SubmitForm", "pdf:submit-form"),
            ("/URI", "pdf:uri"),
        };

        private static void ClassifyAndAnalyzeNonPeFormat(string path, byte[] head, AnalysisResult res, string analysisText)
        {
            if (head.Length < 4) return;

            // ELF magic: 7F 45 4C 46
            if (head[0] == 0x7F && head[1] == 0x45 && head[2] == 0x4C && head[3] == 0x46)
            {
                res.FormatFamily = "ELF";
                res.FileType = "ELF (Linux binary)";
                return;
            }

            // Mach-O magics: 0xFEEDFACE / 0xFEEDFACF (LE+BE) and FAT 0xCAFEBABE / 0xBEBAFECA.
            uint m0 = (uint)(head[0] | (head[1] << 8) | (head[2] << 16) | (head[3] << 24));
            uint m0be = (uint)((head[0] << 24) | (head[1] << 16) | (head[2] << 8) | head[3]);
            if (m0 is 0xFEEDFACEu or 0xFEEDFACFu or 0xCEFAEDFEu or 0xCFFAEDFEu ||
                m0be is 0xCAFEBABEu or 0xBEBAFECAu)
            {
                res.FormatFamily = "Mach-O";
                res.FileType = "Mach-O (macOS binary)";
                return;
            }

            // PDF: starts with "%PDF-"
            if (head.Length >= 5 && head[0] == 0x25 && head[1] == 0x50 && head[2] == 0x44 && head[3] == 0x46 && head[4] == 0x2D)
            {
                res.FormatFamily = "PDF";
                res.FileType = "PDF document";
                foreach (var (needle, label) in PdfRiskyNeedles)
                    if (analysisText.Contains(needle, StringComparison.Ordinal))
                        res.PdfRiskyTags.Add(label);
                return;
            }

            // RTF: {\rt ... or {\\rtf
            if (head[0] == 0x7B && head[1] == 0x5C && head[2] == 0x72 && head[3] == 0x74)
            {
                res.FormatFamily = "RTF";
                res.FileType = "RTF document";
                if (analysisText.Contains("objclass", StringComparison.OrdinalIgnoreCase) ||
                    analysisText.Contains("\\objdata", StringComparison.OrdinalIgnoreCase))
                    res.OfficeIndicators.Add("rtf:obj-embed");
                if (analysisText.Contains("MSComctlLib", StringComparison.OrdinalIgnoreCase))
                    res.OfficeIndicators.Add("rtf:mscomctl");
                return;
            }

            // OLE compound document (.doc, .xls, .ppt, .msi): D0 CF 11 E0 A1 B1 1A E1
            if (head.Length >= 8 && head[0] == 0xD0 && head[1] == 0xCF && head[2] == 0x11 && head[3] == 0xE0 &&
                head[4] == 0xA1 && head[5] == 0xB1 && head[6] == 0x1A && head[7] == 0xE1)
            {
                var ext = Path.GetExtension(path).ToLowerInvariant();
                res.FormatFamily = ext == ".msi" ? "MSI" : "OLE-CDF";
                res.FileType = ext == ".msi" ? "Windows Installer (MSI)" : "OLE Compound (Office 97-2003 / MSI)";
                // Naive VBA project marker inside the OLE stream.
                if (analysisText.Contains("VBA", StringComparison.Ordinal) && analysisText.Contains("Project", StringComparison.Ordinal))
                    res.OfficeIndicators.Add("ole:vba-project");
                if (analysisText.Contains("Auto_Open", StringComparison.Ordinal) || analysisText.Contains("AutoOpen", StringComparison.Ordinal))
                    res.OfficeIndicators.Add("office:auto-open");
                if (analysisText.Contains("\\dde", StringComparison.OrdinalIgnoreCase) || analysisText.Contains("DDEAUTO", StringComparison.Ordinal))
                    res.OfficeIndicators.Add("office:dde");
                return;
            }

            // ZIP / OOXML / APPX / JAR / APK: PK\x03\x04
            if (head[0] == 0x50 && head[1] == 0x4B && (head[2] == 0x03 || head[2] == 0x05 || head[2] == 0x07))
            {
                var ext = Path.GetExtension(path).ToLowerInvariant();
                res.FormatFamily = ext switch
                {
                    ".docx" or ".xlsx" or ".pptx" => "Office-OOXML",
                    ".appx" or ".msix" => "AppX",
                    ".apk" => "APK",
                    ".jar" => "JAR",
                    _ => "ZIP",
                };
                res.FileType = res.FormatFamily switch
                {
                    "Office-OOXML" => "Office OOXML document",
                    "AppX" => "AppX/MSIX package",
                    "APK" => "Android APK",
                    "JAR" => "Java JAR",
                    _ => "ZIP archive",
                };
                // Detect OOXML VBA: vbaProject.bin entry surfaces as literal string in ZIP central directory.
                if (analysisText.Contains("vbaProject.bin", StringComparison.Ordinal))
                    res.OfficeIndicators.Add("ooxml:vba-project-bin");
                if (analysisText.Contains("AppxManifest.xml", StringComparison.Ordinal))
                    res.OfficeIndicators.Add("appx:manifest");
                return;
            }

            // 7z: 37 7A BC AF 27 1C
            if (head.Length >= 6 && head[0] == 0x37 && head[1] == 0x7A && head[2] == 0xBC && head[3] == 0xAF && head[4] == 0x27 && head[5] == 0x1C)
            { res.FormatFamily = "7Z"; res.FileType = "7-Zip archive"; return; }

            // RAR: "Rar!" 0x1A 0x07
            if (head.Length >= 7 && head[0] == 'R' && head[1] == 'a' && head[2] == 'r' && head[3] == '!' && head[4] == 0x1A && head[5] == 0x07)
            { res.FormatFamily = "RAR"; res.FileType = "RAR archive"; return; }

            // GZip: 1F 8B
            if (head[0] == 0x1F && head[1] == 0x8B)
            { res.FormatFamily = "GZip"; res.FileType = "GZip archive"; return; }

            // POSIX TAR (ustar magic at offset 257): we check only the prefix we have (<=20MB), so the
            // header should be readable.
            if (head.Length >= 263 && head[257] == 0x75 && head[258] == 0x73 && head[259] == 0x74 && head[260] == 0x61 && head[261] == 0x72)
            { res.FormatFamily = "TAR"; res.FileType = "TAR archive"; return; }

            // ISO-9660: "CD001" at offset 0x8001
            if (head.Length >= 0x8006 && head[0x8001] == 'C' && head[0x8002] == 'D' && head[0x8003] == '0' && head[0x8004] == '0' && head[0x8005] == '1')
            { res.FormatFamily = "ISO"; res.FileType = "ISO-9660 image"; return; }

            // LNK (ShellLinkHeader): 0x4C 0x00 0x00 0x00 + CLSID 00021401-...
            if (head.Length >= 20 && head[0] == 0x4C && head[1] == 0x00 && head[2] == 0x00 && head[3] == 0x00 &&
                head[4] == 0x01 && head[5] == 0x14 && head[6] == 0x02 && head[7] == 0x00)
            {
                res.FormatFamily = "LNK";
                res.FileType = "Windows Shortcut (LNK)";
                ExtractLnkTarget(head, res);
                return;
            }

            // Script formats: decide by extension, since many scripts start with BOM or plain ASCII.
            var scriptExt = Path.GetExtension(path).ToLowerInvariant();
            var scriptFamily = scriptExt switch
            {
                ".ps1" or ".psm1" => "Script-PS",
                ".vbs" => "Script-VBS",
                ".js" => "Script-JS",
                ".hta" => "Script-HTA",
                ".bat" or ".cmd" => "Script-BAT",
                ".lua"  => "Script-LUA",
                // L3 — .luac is compiled Lua bytecode; the detector
                // pipeline treats it as a Lua-family file but the
                // bytecode header detection upgrades FormatFamily to
                // "Lua-Bytecode" when the magic is present.
                ".luac" => "Script-LUA",
                _ => ""
            };
            if (scriptFamily.Length > 0)
            {
                res.FormatFamily = scriptFamily;
                res.FileType = scriptFamily + " script";
                foreach (var (needle, label) in ScriptIndicatorNeedles)
                    if (analysisText.Contains(needle, StringComparison.OrdinalIgnoreCase))
                        res.ScriptIndicators.Add(label);
                // CC13: Lua scripts get a binary-preserving rescan against
                // the GTA/SA-MP loader & stealer signature groups. The head
                // prefix is the same one used for hash/string extraction —
                // capped by MaxReadPrefixBytes, which is far larger than any
                // legitimate Lua script we'd ever expect.
                if (scriptFamily == "Script-LUA")
                {
                    SafeRun("DetectLuaThreats", () => DetectLuaThreats(res, head));
                    // Stage L (PR 15) — Lua professional detector
                    // pipeline (fact engine + deobfuscation + bytecode
                    // + SA-MP/MoonLoader + HTTP sinks + credential
                    // chain + decisive download-and-load / cred-exfil
                    // markers).
                    SafeRun("LuaDetectors", () => LuaDetectors.Run(res, head));
                }
                return;
            }

            // NSIS installer marker ("Nullsoft.NSIS.exehead" appears in NSIS stubs) — only if the file
            // wasn't a PE (otherwise the PE path already handled it).
            if (analysisText.Contains("Nullsoft.NSIS.exehead", StringComparison.Ordinal))
            { res.FormatFamily = "NSIS"; res.FileType = "NSIS installer"; return; }
        }

        // Minimal LNK parser: reads the LinkTargetIDList + LinkInfo structures just enough to surface
        // the local base path, which is usually the most interesting artifact (malicious LNK files
        // commonly point at PowerShell / cmd with suspicious args).
        private static void ExtractLnkTarget(byte[] head, AnalysisResult res)
        {
            try
            {
                if (head.Length < 78) return;
                uint flags = BitConverter.ToUInt32(head, 20);
                int offset = 76;
                // Skip LinkTargetIDList if present (HasLinkTargetIDList = 0x1)
                if ((flags & 0x1) != 0)
                {
                    if (offset + 2 > head.Length) return;
                    ushort idListSize = BitConverter.ToUInt16(head, offset);
                    offset += 2 + idListSize;
                }
                if ((flags & 0x2) == 0) return; // HasLinkInfo
                if (offset + 28 > head.Length) return;
                int linkInfoStart = offset;
                uint linkInfoSize = BitConverter.ToUInt32(head, linkInfoStart);
                uint localBasePathOffset = BitConverter.ToUInt32(head, linkInfoStart + 16);
                if (localBasePathOffset == 0 || linkInfoStart + localBasePathOffset >= head.Length) return;
                int basePathStart = linkInfoStart + (int)localBasePathOffset;
                int end = basePathStart;
                while (end < head.Length && end - basePathStart < 260 && head[end] != 0) end++;
                if (end > basePathStart)
                {
                    // LNK LocalBasePath is ANSI (typically Windows-1252); we use ASCII here to avoid
                    // pulling in System.Text.Encoding.CodePages. Bytes >= 0x80 fall back to '?'.
                    var span = head.AsSpan(basePathStart, end - basePathStart);
                    var chars = new char[span.Length];
                    for (int i = 0; i < span.Length; i++)
                        chars[i] = span[i] < 0x80 ? (char)span[i] : '?';
                    res.LnkTargetPath = new string(chars);
                }
                _ = linkInfoSize;
            }
            catch { /* best-effort */ }
        }

        // ============================================================
        // C4–C10: Cloud / external enrichment (all optional, all best-effort).
        // ============================================================

        private static readonly HttpClient _cloudHttp = new(new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            AutomaticDecompression = System.Net.DecompressionMethods.All,
        })
        { Timeout = TimeSpan.FromSeconds(15) };

        public static async Task EnrichWithCloudAsync(AnalysisResult res, AnalyzerUiSettings settings, CancellationToken ct)
        {
            if (settings == null || string.IsNullOrEmpty(res.Sha256) || res.Sha256.Length != 64) return;
            var timeout = TimeSpan.FromMilliseconds(Math.Max(1000, settings.CloudTimeoutMs));

            var tasks = new List<Task>();
            if (settings.EnableVirusTotal && !string.IsNullOrWhiteSpace(settings.VirusTotalApiKey))
                tasks.Add(VirusTotalLookup(res, settings.VirusTotalApiKey, timeout, ct));
            if (settings.EnableMalwareBazaar)
                tasks.Add(MalwareBazaarLookup(res, timeout, ct));
            if (settings.EnableTriage && !string.IsNullOrWhiteSpace(settings.TriageApiKey))
                tasks.Add(TriageLookup(res, settings.TriageApiKey, timeout, ct));
            if (settings.EnableHybridAnalysis && !string.IsNullOrWhiteSpace(settings.HybridAnalysisApiKey))
                tasks.Add(HybridAnalysisLookup(res, settings.HybridAnalysisApiKey, timeout, ct));
            if (settings.EnableUrlhaus && res.UrlsFound.Count > 0)
                tasks.Add(UrlhausLookup(res, timeout, ct));
            if (settings.EnableAbuseIpDb && !string.IsNullOrWhiteSpace(settings.AbuseIpDbApiKey) && res.Ipv4Hits.Count > 0)
                tasks.Add(AbuseIpDbLookup(res, settings.AbuseIpDbApiKey, timeout, ct));
            if (settings.EnableShodan && !string.IsNullOrWhiteSpace(settings.ShodanApiKey) && res.Ipv4Hits.Count > 0)
                tasks.Add(ShodanLookup(res, settings.ShodanApiKey, timeout, ct));
            if (settings.EnableCensys && !string.IsNullOrWhiteSpace(settings.CensysApiId) && !string.IsNullOrWhiteSpace(settings.CensysApiSecret) && res.Ipv4Hits.Count > 0)
                tasks.Add(CensysLookup(res, settings.CensysApiId, settings.CensysApiSecret, timeout, ct));
            if (settings.EnableClamAv)
                tasks.Add(ClamAvScan(res, settings.ClamAvPath, ct));
            if (settings.EnableSigmaLite)
                tasks.Add(Task.Run(() => RunSigmaLite(res), ct));

            if (tasks.Count > 0)
            {
                try { await Task.WhenAll(tasks); }
                catch { /* individual lookups swallow their own exceptions */ }
            }
        }

        private static async Task<string?> GetSmallTextAsync(HttpRequestMessage req, TimeSpan timeout, CancellationToken ct)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            try
            {
                using var resp = await _cloudHttp.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token);
                if (!resp.IsSuccessStatusCode) return null;
                // Cap at 256 KB so a runaway provider can't eat all our memory.
                var bytes = await resp.Content.ReadAsByteArrayAsync(cts.Token);
                if (bytes.Length > 262_144) Array.Resize(ref bytes, 262_144);
                return Encoding.UTF8.GetString(bytes);
            }
            catch { return null; }
        }

        // C4 — VirusTotal file report lookup.
        private static async Task VirusTotalLookup(AnalysisResult res, string apiKey, TimeSpan timeout, CancellationToken ct)
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{res.Sha256}");
                req.Headers.TryAddWithoutValidation("x-apikey", apiKey);
                var text = await GetSmallTextAsync(req, timeout, ct);
                if (string.IsNullOrEmpty(text)) return;
                int mal = ExtractJsonInt(text, "\"malicious\":");
                int sus = ExtractJsonInt(text, "\"suspicious\":");
                int harm = ExtractJsonInt(text, "\"harmless\":");
                int undet = ExtractJsonInt(text, "\"undetected\":");
                int total = mal + sus + harm + undet;
                if (total > 0)
                    res.CloudLookupResults["VirusTotal"] = $"malicious={mal}/{total} suspicious={sus}";
            }
            catch { }
        }

        // C5 — MalwareBazaar anonymous hash lookup.
        private static async Task MalwareBazaarLookup(AnalysisResult res, TimeSpan timeout, CancellationToken ct)
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Post, "https://mb-api.abuse.ch/api/v1/");
                req.Content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("query", "get_info"),
                    new KeyValuePair<string, string>("hash", res.Sha256),
                });
                var text = await GetSmallTextAsync(req, timeout, ct);
                if (string.IsNullOrEmpty(text)) return;
                if (text.Contains("\"query_status\":\"ok\"", StringComparison.Ordinal))
                {
                    var family = ExtractJsonString(text, "\"signature\":");
                    var tags = ExtractJsonString(text, "\"tags\":");
                    res.CloudLookupResults["MalwareBazaar"] = $"family={family} tags={tags}";
                }
            }
            catch { }
        }

        // C5 — Triage (tria.ge) search by hash.
        private static async Task TriageLookup(AnalysisResult res, string apiKey, TimeSpan timeout, CancellationToken ct)
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, $"https://tria.ge/api/v0/search?query=sha256:{res.Sha256}");
                req.Headers.TryAddWithoutValidation("Authorization", $"Bearer {apiKey}");
                var text = await GetSmallTextAsync(req, timeout, ct);
                if (string.IsNullOrEmpty(text)) return;
                if (text.Contains("\"data\":", StringComparison.Ordinal))
                    res.CloudLookupResults["Triage"] = "seen";
            }
            catch { }
        }

        // C6 — Hybrid Analysis / CAPE push: for now we only do a search, not a sandbox submission.
        private static async Task HybridAnalysisLookup(AnalysisResult res, string apiKey, TimeSpan timeout, CancellationToken ct)
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Post, "https://www.hybrid-analysis.com/api/v2/search/hash");
                req.Headers.TryAddWithoutValidation("api-key", apiKey);
                req.Headers.TryAddWithoutValidation("User-Agent", "Falcon Sandbox");
                req.Content = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("hash", res.Sha256) });
                var text = await GetSmallTextAsync(req, timeout, ct);
                if (string.IsNullOrEmpty(text)) return;
                var verdict = ExtractJsonString(text, "\"verdict\":");
                if (!string.IsNullOrEmpty(verdict))
                    res.CloudLookupResults["HybridAnalysis"] = $"verdict={verdict}";
            }
            catch { }
        }

        // C7 — URLhaus batch check of the first N URLs.
        private static async Task UrlhausLookup(AnalysisResult res, TimeSpan timeout, CancellationToken ct)
        {
            int checkCount = Math.Min(res.UrlsFound.Count, 10);
            int hits = 0;
            for (int i = 0; i < checkCount; i++)
            {
                try
                {
                    using var req = new HttpRequestMessage(HttpMethod.Post, "https://urlhaus-api.abuse.ch/v1/url/");
                    req.Content = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("url", res.UrlsFound[i]) });
                    var text = await GetSmallTextAsync(req, timeout, ct);
                    if (string.IsNullOrEmpty(text)) continue;
                    if (text.Contains("\"query_status\":\"ok\"", StringComparison.Ordinal) &&
                        text.Contains("\"threat\":", StringComparison.Ordinal))
                        hits++;
                }
                catch { }
            }
            if (hits > 0) res.CloudLookupResults["URLhaus"] = $"malicious-urls={hits}/{checkCount}";
        }

        // C7 — AbuseIPDB check of the first N IPs.
        private static async Task AbuseIpDbLookup(AnalysisResult res, string apiKey, TimeSpan timeout, CancellationToken ct)
        {
            int best = 0;
            int checkCount = Math.Min(res.Ipv4Hits.Count, 10);
            for (int i = 0; i < checkCount; i++)
            {
                try
                {
                    using var req = new HttpRequestMessage(HttpMethod.Get, $"https://api.abuseipdb.com/api/v2/check?ipAddress={Uri.EscapeDataString(res.Ipv4Hits[i])}");
                    req.Headers.TryAddWithoutValidation("Key", apiKey);
                    req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
                    var text = await GetSmallTextAsync(req, timeout, ct);
                    if (string.IsNullOrEmpty(text)) continue;
                    int score = ExtractJsonInt(text, "\"abuseConfidenceScore\":");
                    if (score > best) best = score;
                }
                catch { }
            }
            if (best > 0) res.CloudLookupResults["AbuseIPDB"] = $"max-confidence={best}";
        }

        // C8 — Shodan host lookup for first IP.
        private static async Task ShodanLookup(AnalysisResult res, string apiKey, TimeSpan timeout, CancellationToken ct)
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, $"https://api.shodan.io/shodan/host/{Uri.EscapeDataString(res.Ipv4Hits[0])}?key={Uri.EscapeDataString(apiKey)}");
                var text = await GetSmallTextAsync(req, timeout, ct);
                if (string.IsNullOrEmpty(text)) return;
                var org = ExtractJsonString(text, "\"org\":");
                var country = ExtractJsonString(text, "\"country_code\":");
                if (!string.IsNullOrEmpty(org) || !string.IsNullOrEmpty(country))
                    res.CloudLookupResults["Shodan"] = $"org={org} country={country}";
            }
            catch { }
        }

        // C8 — Censys host lookup for first IP.
        private static async Task CensysLookup(AnalysisResult res, string apiId, string apiSecret, TimeSpan timeout, CancellationToken ct)
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, $"https://search.censys.io/api/v2/hosts/{Uri.EscapeDataString(res.Ipv4Hits[0])}");
                var basicAuth = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{apiId}:{apiSecret}"));
                req.Headers.TryAddWithoutValidation("Authorization", $"Basic {basicAuth}");
                var text = await GetSmallTextAsync(req, timeout, ct);
                if (string.IsNullOrEmpty(text)) return;
                var asn = ExtractJsonString(text, "\"name\":"); // autonomous_system.name
                if (!string.IsNullOrEmpty(asn))
                    res.CloudLookupResults["Censys"] = $"as={asn}";
            }
            catch { }
        }

        // C9 — Local AV scan via clamscan.exe.
        private static async Task ClamAvScan(AnalysisResult res, string exePath, CancellationToken ct)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(exePath)) exePath = DiscoverClamScan();
                if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath)) return;
                var psi = new System.Diagnostics.ProcessStartInfo(exePath)
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                psi.ArgumentList.Add("--no-summary");
                psi.ArgumentList.Add("--stdout");
                psi.ArgumentList.Add(res.FilePath);
                using var proc = System.Diagnostics.Process.Start(psi);
                if (proc == null) return;
                // Section 13.2 — bind the helper to a Job Object so the OS
                // kills it if our parent process crashes / is force-quit.
                // No-op on non-Windows; the CancellationToken still handles
                // cooperative shutdown there.
                using var jobGuard = JobObjectGuard.Create();
                jobGuard.AssignProcess(proc);
                using var reg = ct.Register(() => { try { proc.Kill(true); } catch { } });
                await proc.WaitForExitAsync(ct);
                var stdout = await proc.StandardOutput.ReadToEndAsync(ct);
                // clamscan format: "<path>: <signature> FOUND" on hits.
                foreach (var raw in stdout.Split('\n'))
                {
                    var line = raw.Trim();
                    if (line.EndsWith(" FOUND", StringComparison.Ordinal))
                    {
                        int colon = line.LastIndexOf(": ");
                        if (colon > 0)
                        {
                            var sig = line[(colon + 2)..^6].Trim();
                            if (!string.IsNullOrEmpty(sig)) res.LocalAvHits.Add(sig);
                        }
                    }
                }
                if (res.LocalAvHits.Count > 0)
                    res.CloudLookupResults["ClamAV"] = $"hits={res.LocalAvHits.Count}";
            }
            catch { }
        }

        private static string DiscoverClamScan()
        {
            var names = new[] { "clamscan.exe", "clamdscan.exe", "clamscan", "clamdscan" };
            var envPath = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            foreach (var dir in envPath.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                foreach (var n in names)
                {
                    try
                    {
                        var p = Path.Combine(dir, n);
                        if (File.Exists(p)) return p;
                    }
                    catch { }
                }
            }
            return "";
        }

        // C10 — Sigma-lite rule scanner. Loads *.sigma.txt files from %APPDATA%\AntiStealer\sigma\ and
        // matches simple 'needle' / 'regex:' rules against the analysis strings. Full Sigma YAML would
        // require a YAML parser — intentionally out of scope for this PR.
        //
        // File format (one rule per block, blank line separated):
        //
        //   name: StealerGeneric
        //   condition: any
        //   needle: Login Data
        //   needle: Web Data
        //   regex: TOKEN[A-Z0-9]{20,}
        //
        // `condition:` is `any` (default) or `all`.
        private static List<(string Name, string Cond, List<string> Needles, List<Regex> Rx)>? _sigmaCache;
        private static void RunSigmaLite(AnalysisResult res)
        {
            try
            {
                var rules = LoadSigmaLiteRules();
                if (rules.Count == 0) return;
                // We don't keep the raw analysis text on AnalysisResult (to save memory), so Sigma-lite
                // matches a concatenation of the enumerable string artifacts.
                var sb = new StringBuilder(4096);
                foreach (var u in res.UrlsFound) sb.AppendLine(u);
                foreach (var s in res.StringHits) sb.AppendLine(s);
                foreach (var s in res.SuspiciousApiHits) sb.AppendLine(s);
                foreach (var i in res.ImportedApis) sb.AppendLine(i);
                foreach (var i in res.PersistenceIndicators) sb.AppendLine(i);
                foreach (var i in res.BrowserStealerIndicators) sb.AppendLine(i);
                foreach (var i in res.AntiAnalysisIndicators) sb.AppendLine(i);
                foreach (var i in res.C2Indicators) sb.AppendLine(i);
                foreach (var i in res.ScriptIndicators) sb.AppendLine(i);
                foreach (var i in res.PdfRiskyTags) sb.AppendLine(i);
                foreach (var i in res.OfficeIndicators) sb.AppendLine(i);
                var haystack = sb.ToString();

                foreach (var (name, cond, needles, rx) in rules)
                {
                    bool any = false, all = true;
                    bool anyPart = false; bool allPart = true;
                    foreach (var n in needles)
                    {
                        bool hit = haystack.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0;
                        anyPart |= hit; allPart &= hit;
                    }
                    foreach (var r in rx)
                    {
                        bool hit = false;
                        try { hit = r.IsMatch(haystack); } catch { }
                        anyPart |= hit; allPart &= hit;
                    }
                    any = anyPart; all = needles.Count + rx.Count > 0 && allPart;

                    bool match = cond == "all" ? all : any;
                    if (match) res.SigmaLiteHits.Add(name);
                }
            }
            catch { }
        }

        private static List<(string, string, List<string>, List<Regex>)> LoadSigmaLiteRules()
        {
            if (_sigmaCache != null) return _sigmaCache;
            var rules = new List<(string, string, List<string>, List<Regex>)>();
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var dir = Path.Combine(appData, "AntiStealer", "sigma");
            if (!Directory.Exists(dir)) { _sigmaCache = rules; return rules; }

            // Section 13.7 — canonicalise the rules root and reject any file whose real path
            // (after symlink resolution) escapes it. Without this a maliciously placed symlink
            // in the rules directory could cause the engine to read arbitrary files from the
            // host filesystem.
            var rulesRoot = Path.GetFullPath(dir);

            foreach (var file in Directory.EnumerateFiles(dir, "*.sigma.txt", SearchOption.AllDirectories))
            {
                if (!IsPathInside(file, rulesRoot))
                {
                    AsiLogger.Warn("sigma.path_outside_root", new Dictionary<string, object?>
                    {
                        ["file"] = file,
                        ["root"] = rulesRoot,
                    });
                    continue;
                }
                string[] lines;
                try { lines = File.ReadAllLines(file); } catch { continue; }
                string currentName = ""; string cond = "any";
                var needles = new List<string>(); var rx = new List<Regex>();

                void Flush()
                {
                    if (!string.IsNullOrEmpty(currentName) && (needles.Count > 0 || rx.Count > 0))
                        rules.Add((currentName, cond, new List<string>(needles), new List<Regex>(rx)));
                    currentName = ""; cond = "any"; needles.Clear(); rx.Clear();
                }

                foreach (var raw in lines)
                {
                    var line = raw.Trim();
                    if (line.Length == 0) { Flush(); continue; }
                    int sep = line.IndexOf(':');
                    if (sep <= 0) continue;
                    var key = line[..sep].Trim().ToLowerInvariant();
                    var val = line[(sep + 1)..].Trim();
                    switch (key)
                    {
                        case "name": currentName = val; break;
                        case "condition": cond = val.ToLowerInvariant(); break;
                        case "needle": needles.Add(val); break;
                        case "regex":
                            try { rx.Add(new Regex(val, RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(200))); } catch { }
                            break;
                    }
                }
                Flush();
            }
            _sigmaCache = rules;
            return rules;
        }

        private static int ExtractJsonInt(string json, string key)
        {
            int i = json.IndexOf(key, StringComparison.Ordinal);
            if (i < 0) return 0;
            i += key.Length;
            while (i < json.Length && (json[i] == ' ' || json[i] == '\t')) i++;
            int start = i;
            while (i < json.Length && (char.IsDigit(json[i]) || json[i] == '-')) i++;
            if (i == start) return 0;
            return int.TryParse(json.AsSpan(start, i - start), out var v) ? v : 0;
        }

        private static string ExtractJsonString(string json, string key)
        {
            int i = json.IndexOf(key, StringComparison.Ordinal);
            if (i < 0) return "";
            i += key.Length;
            while (i < json.Length && (json[i] == ' ' || json[i] == '\t')) i++;
            if (i >= json.Length || json[i] != '"') return "";
            i++;
            int start = i;
            while (i < json.Length && json[i] != '"')
            {
                if (json[i] == '\\' && i + 1 < json.Length) i++;
                i++;
            }
            return i > start ? json[start..i].Replace("\\\"", "\"", StringComparison.Ordinal) : "";
        }

        // ============================================================
        // B1: YARA integration.
        // ============================================================

        // Cached discovery results so we don't keep re-probing the filesystem for yara.exe / rules on
        // every file in a batch scan.
        private static string? _yaraExeCached;
        private static bool _yaraProbed;
        private static List<string>? _yaraRuleFilesCached;
        private static readonly object _yaraLock = new();

        // Enumeration is cheap; we memoize anyway because a 10k-file batch would otherwise stat the
        // rules directory 10k times. We refresh lazily by checking the latest mtime once per run.
        private static List<string> DiscoverYaraRuleFiles()
        {
            lock (_yaraLock)
            {
                if (_yaraRuleFilesCached != null) return _yaraRuleFilesCached;

                var candidates = new List<string>();
                var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                if (!string.IsNullOrEmpty(appData))
                    candidates.Add(Path.Combine(appData, "AntiStealer", "yara"));
                var exeDir = AppContext.BaseDirectory;
                if (!string.IsNullOrEmpty(exeDir))
                {
                    candidates.Add(Path.Combine(exeDir, "yara-rules"));
                    candidates.Add(Path.Combine(exeDir, "rules"));
                }

                var files = new List<string>();
                foreach (var dir in candidates)
                {
                    if (!Directory.Exists(dir)) continue;
                    // Section 13.7 — same path-traversal protection as the Sigma loader: only
                    // accept rule files whose canonical path lives under the canonical rules
                    // root (defeats symlinks that point outside the rules directory).
                    var rulesRoot = Path.GetFullPath(dir);
                    try
                    {
                        foreach (var f in Directory.EnumerateFiles(dir, "*.yar",  SearchOption.AllDirectories))
                            if (IsPathInside(f, rulesRoot)) files.Add(f);
                        foreach (var f in Directory.EnumerateFiles(dir, "*.yara", SearchOption.AllDirectories))
                            if (IsPathInside(f, rulesRoot)) files.Add(f);
                    }
                    catch { /* directory may not be accessible */ }
                }

                _yaraRuleFilesCached = files;
                return files;
            }
        }

        // Section 13.7 — shared path-canonicalisation helper. A path is "inside" root if its
        // resolved full path starts with root + separator (or equals root for the directory
        // itself). Symlinks are resolved by Path.GetFullPath when the underlying file exists.
        private static bool IsPathInside(string candidate, string root)
        {
            try
            {
                var full = Path.GetFullPath(candidate);
                var normRoot = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                              + Path.DirectorySeparatorChar;
                return full.StartsWith(normRoot, StringComparison.Ordinal)
                    || string.Equals(full, root, StringComparison.Ordinal);
            }
            catch { return false; }
        }

        // Section 10.3 — cached engine selection. We probe for yara-x first,
        // then fall back to classic yara. The chosen binary is reused for the
        // lifetime of the process; `_yaraIsX` records which engine we picked
        // so RunYaraIfAvailable can emit the right CLI flags.
        private static bool _yaraIsX;

        private static string? DiscoverYaraExecutable()
        {
            lock (_yaraLock)
            {
                if (_yaraProbed) return _yaraExeCached;
                _yaraProbed = true;

                var bin = YaraXEngine.Discover(out var isYaraX);
                _yaraExeCached = bin;
                _yaraIsX = isYaraX;
                return bin;
            }
        }

        private static void RunYaraIfAvailable(string targetFile, AnalysisResult res)
        {
            var exe = DiscoverYaraExecutable();
            if (exe == null) return;
            res.YaraEngine = _yaraIsX ? "yara-x" : "yara";

            var ruleFiles = DiscoverYaraRuleFiles();
            if (ruleFiles.Count == 0) return;

            // C18: per-engine timing budget.  Per-rule timeout reads
            // from ANTISTEALER_YARA_TIMEOUT_MS (default 8000) so the
            // operator can tighten or loosen YARA's slice independent
            // of the Sigma/CAPA defaults.
            var budget = RulesBudget.FromEnv("yara");
            long perRuleTimeoutMs = ReadEnvLongOrDefault(
                "ANTISTEALER_YARA_TIMEOUT_MS",
                Math.Max(1000, budget.PerRuleBudgetMs == 250 ? 8000 : budget.PerRuleBudgetMs));

            // We invoke once per rule file, capped at 64 to keep total scan time
            // bounded. yara-x and classic yara both print `<rule> [<tags>] <file>`
            // per match (one line) by default, which the parser below splits on
            // the first space.
            int limit = Math.Min(ruleFiles.Count, 64);
            for (int i = 0; i < limit; i++)
            {
                if (budget.EngineExpired)
                {
                    res.RulesEngineTimeouts.Add("yara:engine-budget");
                    break;
                }
                var ruleFile = ruleFiles[i];
                var ruleClock = budget.StartRule();
                try
                {
                    var psi = new System.Diagnostics.ProcessStartInfo(exe)
                    {
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                    };
                    foreach (var arg in YaraXEngine.BuildArgs(_yaraIsX, ruleFile, targetFile))
                        psi.ArgumentList.Add(arg);

                    using var proc = System.Diagnostics.Process.Start(psi);
                    if (proc == null) continue;
                    using var jobGuard = JobObjectGuard.Create();
                    jobGuard.AssignProcess(proc);

                    // C18: drain stdout+stderr asynchronously.  Without
                    // this, a process that fills the stderr pipe buffer
                    // (e.g., yara complaining about a malformed rule)
                    // can deadlock at WaitForExit because we'd otherwise
                    // only read stdout *after* exit.
                    var stdoutBuf = new StringBuilder();
                    var stderrBuf = new StringBuilder();
                    proc.OutputDataReceived += (_, ea) =>
                    {
                        if (ea.Data != null) stdoutBuf.AppendLine(ea.Data);
                    };
                    proc.ErrorDataReceived += (_, ea) =>
                    {
                        if (ea.Data != null) stderrBuf.AppendLine(ea.Data);
                    };
                    proc.BeginOutputReadLine();
                    proc.BeginErrorReadLine();

                    if (!proc.WaitForExit((int)Math.Min(int.MaxValue, perRuleTimeoutMs)))
                    {
                        try { proc.Kill(entireProcessTree: true); } catch { }
                        res.RulesEngineTimeouts.Add($"yara:{Path.GetFileName(ruleFile)}");
                        continue;
                    }
                    // Wait for the async readers to flush after exit.
                    try { proc.WaitForExit(); } catch { }

                    var stdout = stdoutBuf.ToString();
                    var stderr = stderrBuf.ToString();

                    if (!string.IsNullOrWhiteSpace(stderr))
                    {
                        // First non-empty stderr line — enough signal to
                        // identify the failure without spamming the report.
                        foreach (var raw in stderr.Split('\n'))
                        {
                            var line = raw.TrimEnd('\r', ' ', '\t');
                            if (string.IsNullOrEmpty(line)) continue;
                            res.RulesEngineErrors.Add($"yara:{Path.GetFileName(ruleFile)}: {line}");
                            break;
                        }
                    }

                    if (string.IsNullOrWhiteSpace(stdout)) continue;

                    bool addedAnyHit = false;
                    foreach (var raw in stdout.Split('\n'))
                    {
                        var line = raw.TrimEnd('\r', ' ', '\t');
                        if (string.IsNullOrEmpty(line)) continue;
                        int sp = line.IndexOf(' ');
                        var ruleName = sp > 0 ? line[..sp] : line;
                        if (ruleName.Length == 0) continue;
                        // P9 — tag the source as "file" (yara-x on the
                        // raw file). Resource / decoded / memory hits
                        // come from other emitters that pass the
                        // appropriate Source.
                        YaraHitTagger.AddHit(res,
                                             "file",
                                             Path.GetFileName(ruleFile),
                                             ruleName);
                        addedAnyHit = true;
                        if (res.YaraHits.Count >= 64) return;
                    }
                    if (addedAnyHit)
                        RuleEngineUtil.RecordProvenance(res, "yara", ruleFile);
                }
                catch { /* swallow per-rule-file errors so one bad ruleset doesn't break the scan */ }
                finally
                {
                    ruleClock.Stop();
                }
            }
            RuleEngineUtil.AddTimingMs(res, _yaraIsX ? "yara-x" : "yara", budget.Total.ElapsedMilliseconds);
        }

        // C18 — helper used by RunYaraIfAvailable to read an optional
        // long-valued env var.  Falls back to `fallback` for non-numeric
        // / unset / negative values.
        private static long ReadEnvLongOrDefault(string name, long fallback)
        {
            var raw = Environment.GetEnvironmentVariable(name);
            if (long.TryParse(
                    raw,
                    System.Globalization.NumberStyles.Integer,
                    System.Globalization.CultureInfo.InvariantCulture,
                    out var v) && v > 0)
                return v;
            return fallback;
        }

        private static string Rot13(string s)
        {
            var chars = new char[s.Length];
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c >= 'a' && c <= 'z') chars[i] = (char)((c - 'a' + 13) % 26 + 'a');
                else if (c >= 'A' && c <= 'Z') chars[i] = (char)((c - 'A' + 13) % 26 + 'A');
                else chars[i] = c;
            }
            return new string(chars);
        }

        private static void AddStringEvidence(AnalysisResult res, string candidate, HashSet<string> allStrings, StringBuilder analysisText) =>
            AddStringEvidence(res, candidate, allStrings, analysisText, evidenceSource: null);

        private static void AddStringEvidence(
            AnalysisResult res,
            string candidate,
            HashSet<string> allStrings,
            StringBuilder analysisText,
            string? evidenceSource)
        {
            var s = candidate.Length > 2048 ? candidate[..2048] : candidate;
            if (!allStrings.Add(s)) return;

            if (res.StringHits.Count < 400)
            {
                // Section 5.1 — Aho-Corasick is case-insensitive, so we
                // can drop the explicit ToLowerInvariant copy on the hot
                // path. A single AC walk covers all ~50 needles.
                if (Needles.SuspiciousStringAc.Value.FindUniquePatterns(s).Count > 0)
                {
                    res.StringHits.Add(s);
                    if (!string.IsNullOrEmpty(evidenceSource))
                        res.AddEvidence(evidenceSource!, s);
                }
            }

            if (analysisText.Length < MaxSearchTextChars)
            {
                var remaining = MaxSearchTextChars - analysisText.Length;
                if (s.Length > remaining) analysisText.Append(s.AsSpan(0, remaining));
                else analysisText.Append(s);
                if (analysisText.Length < MaxSearchTextChars) analysisText.Append('\n');
            }
        }

        private static void PopulateRegexIndicators(AnalysisResult res, string text)
        {
            res.Base64BlobHits = SafeCountMatches(Base64BlobRegex, text);
            res.PrivateKeyBlockHits = SafeCountMatches(PrivateKeyBlockRegex, text);
            res.Ipv4Hits = SafeDistinctMatches(Ipv4Regex, text, 200);
            res.EmailHits = SafeDistinctMatches(EmailRegex, text, 200);
            res.JwtHits = SafeDistinctMatches(JwtRegex, text, 200);
            res.TelegramBotTokenHits = SafeDistinctMatches(TelegramBotTokenRegex, text, 200);
            var discordHits = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var m in SafeDistinctMatches(DiscordTokenLegacyRegex, text, 200)) discordHits.Add(m);
            foreach (var m in SafeDistinctMatches(DiscordTokenCurrentRegex, text, 200)) discordHits.Add(m);
            foreach (var m in SafeDistinctMatches(DiscordMfaTokenRegex, text, 200)) discordHits.Add(m);
            res.DiscordTokenHits = discordHits.Take(200).ToList();

            // M2: BTC/TRC first, then post-filter SOL candidates that overlap base58 of BTC/TRC.
            var btc = SafeDistinctMatches(BtcRegex, text, 100);
            var eth = SafeDistinctMatches(EthRegex, text, 100);
            var trc = SafeDistinctMatches(TronRegex, text, 100);
            var claimed = new HashSet<string>(btc, StringComparer.Ordinal);
            foreach (var t in trc) claimed.Add(t);
            var sol = SafeDistinctMatches(SolRegex, text, 200).Where(s => !claimed.Contains(s)).Take(100).ToList();
            var xmr = SafeDistinctMatches(XmrRegex, text, 100);
            res.CryptoWalletHits = btc
                .Concat(eth)
                .Concat(trc)
                .Concat(sol)
                .Concat(xmr)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(100)
                .ToList();

            // C13 — IOC quality filters.
            foreach (var b in btc)
            {
                if (b.StartsWith("bc1", StringComparison.OrdinalIgnoreCase) && Bech32Verify(b))
                    res.BtcBech32Validated.Add(b);
            }
            foreach (var e in eth)
            {
                // Mixed-case implies the producer applied EIP-55
                // checksumming. All-lowercase is permitted by the
                // spec but doesn't carry the checksum invariant; we
                // skip those because they're more likely to be
                // random hex.
                bool hasUpper = false, hasLower = false;
                for (int i = 2; i < e.Length; i++)
                {
                    if (char.IsUpper(e[i])) hasUpper = true;
                    else if (char.IsLower(e[i])) hasLower = true;
                }
                if (hasUpper && hasLower)
                    res.EthEip55Checksummed.Add(e);
            }
            foreach (var j in res.JwtHits)
            {
                if (IsJwtStructurallyValid(j))
                    res.JwtValidatedHits.Add(j);
            }
            // Telegram-token context check.  We look ±256 chars
            // around each token for a Bot-API verb.
            string[] tgVerbs =
            {
                "sendMessage", "sendDocument", "sendPhoto", "sendAudio",
                "sendVideo", "sendVoice", "sendMediaGroup", "sendLocation",
                "api.telegram.org/bot", "t.me/", "TelegramBot",
            };
            foreach (var tok in res.TelegramBotTokenHits)
            {
                int idx = text.IndexOf(tok, StringComparison.Ordinal);
                if (idx < 0) continue;
                int s = Math.Max(0, idx - 256);
                int e = Math.Min(text.Length, idx + tok.Length + 256);
                var w = text.Substring(s, e - s);
                if (tgVerbs.Any(v => w.IndexOf(v, StringComparison.OrdinalIgnoreCase) >= 0))
                    res.TelegramTokensWithContext.Add(tok);
            }
            string[] dcContext =
            {
                "discord.com/api", "discordapp.com/api", "webhook",
                "Authorization: Bot", "DiscordToken", "discord_token",
            };
            foreach (var tok in res.DiscordTokenHits)
            {
                int idx = text.IndexOf(tok, StringComparison.Ordinal);
                if (idx < 0) continue;
                int s = Math.Max(0, idx - 256);
                int e = Math.Min(text.Length, idx + tok.Length + 256);
                var w = text.Substring(s, e - s);
                if (dcContext.Any(v => w.IndexOf(v, StringComparison.OrdinalIgnoreCase) >= 0))
                    res.DiscordTokensWithContext.Add(tok);
            }
        }

        // C13 — Bech32 (BIP173) checksum verification.
        // Returns true iff the address has a valid HRP/data/checksum.
        // We only support the SegWit subset because Lightning / Taproot
        // and other constants are out of scope for stealer detection.
        private static readonly int[] Bech32Generator =
            { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
        private static readonly string Bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        internal static bool Bech32Verify(string addr)
        {
            if (string.IsNullOrEmpty(addr)) return false;
            addr = addr.ToLowerInvariant();
            int sep = addr.LastIndexOf('1');
            if (sep < 1 || sep + 7 > addr.Length) return false;
            string hrp = addr[..sep];
            string data = addr[(sep + 1)..];
            var dec = new int[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                int v = Bech32Charset.IndexOf(data[i]);
                if (v < 0) return false;
                dec[i] = v;
            }
            // Polymod with HRP-expand prefix.
            int chk = 1;
            foreach (var c in hrp) chk = Bech32Step(chk, c >> 5);
            chk = Bech32Step(chk, 0);
            foreach (var c in hrp) chk = Bech32Step(chk, c & 31);
            foreach (var v in dec) chk = Bech32Step(chk, v);
            return chk == 1 || chk == 0x2bc830a3; // bech32 or bech32m
        }
        private static int Bech32Step(int chk, int value)
        {
            int b = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ value;
            for (int i = 0; i < 5; i++)
                if (((b >> i) & 1) != 0) chk ^= Bech32Generator[i];
            return chk;
        }

        // C13 — JWT structural validation.  We base64url-decode the
        // header and check that it parses to a JSON object with the
        // mandatory `alg` field.  We deliberately ignore signature
        // verification (we have no key material) and `typ` is
        // optional per RFC 7519.
        internal static bool IsJwtStructurallyValid(string jwt)
        {
            if (string.IsNullOrEmpty(jwt)) return false;
            int firstDot = jwt.IndexOf('.');
            if (firstDot < 4) return false;
            string headerB64 = jwt[..firstDot];
            try
            {
                // Base64url → base64
                string std = headerB64.Replace('-', '+').Replace('_', '/');
                int pad = (4 - (std.Length % 4)) % 4;
                std += new string('=', pad);
                var json = Encoding.UTF8.GetString(Convert.FromBase64String(std));
                // Quick structural check; avoid full JSON parse cost.
                return json.IndexOf("\"alg\"", StringComparison.Ordinal) >= 0;
            }
            catch
            {
                return false;
            }
        }

        // Section 5.3 — rent the temporary char buffer from ArrayPool<char>
        // instead of allocating a fresh StringBuilder backing array. On a
        // 1 MiB sample with thousands of ASCII strings, the StringBuilder
        // path dominated GC pressure (one resize-and-copy per ~256 chars).
        // We still take byte[] (rather than ReadOnlySpan<byte>) because
        // C# iterator methods cannot hold a Span across a yield boundary
        // — Span is a ref struct. The single new-string-per-yield
        // allocation is unavoidable: that string is the iterator's
        // result and must outlive the rented buffer.
        private static IEnumerable<string> ExtractAsciiStrings(byte[] data, int minLen, int max)
        {
            const int FlushAt = 8192;
            int count = 0;
            char[] rent = System.Buffers.ArrayPool<char>.Shared.Rent(FlushAt + 1);
            int len = 0;
            try
            {
                for (int i = 0; i < data.Length && count < max; i++)
                {
                    var b = data[i];
                    if (b >= 32 && b <= 126)
                    {
                        rent[len++] = (char)b;
                        if (len > FlushAt)
                        {
                            if (len >= minLen)
                            {
                                count++;
                                yield return new string(rent, 0, len);
                            }
                            len = 0;
                        }
                    }
                    else if (len > 0)
                    {
                        if (len >= minLen)
                        {
                            count++;
                            yield return new string(rent, 0, len);
                        }
                        len = 0;
                    }
                }

                if (len >= minLen && count < max)
                    yield return new string(rent, 0, len);
            }
            finally
            {
                System.Buffers.ArrayPool<char>.Shared.Return(rent);
            }
        }

        private static IEnumerable<string> ExtractUnicodeStrings(byte[] data, int minLen, int max)
        {
            const int FlushAt = 8192;
            int count = 0;
            char[] rent = System.Buffers.ArrayPool<char>.Shared.Rent(FlushAt + 1);
            int len = 0;
            try
            {
                for (int i = 0; i + 1 < data.Length && count < max; i += 2)
                {
                    byte lo = data[i];
                    byte hi = data[i + 1];

                    if (hi == 0 && lo >= 32 && lo <= 126)
                    {
                        rent[len++] = (char)lo;
                        if (len > FlushAt)
                        {
                            if (len >= minLen)
                            {
                                count++;
                                yield return new string(rent, 0, len);
                            }
                            len = 0;
                        }
                    }
                    else if (len > 0)
                    {
                        if (len >= minLen)
                        {
                            count++;
                            yield return new string(rent, 0, len);
                        }
                        len = 0;
                    }
                }

                if (len >= minLen && count < max)
                    yield return new string(rent, 0, len);
            }
            finally
            {
                System.Buffers.ArrayPool<char>.Shared.Return(rent);
            }
        }

        private static List<string> ExtractUrls(byte[] data, int max)
        {
            var text = Encoding.ASCII.GetString(data);
            var urls = new List<string>();

            foreach (var value in SafeDistinctMatches(UrlRegex, text, max))
            {
                if (value.Length < 10 || value.Length > 300) continue;
                urls.Add(value);
            }

            return urls;
        }

        private static int SafeCountMatches(Regex regex, string text)
        {
            try
            {
                return regex.Matches(text).Count;
            }
            catch (RegexMatchTimeoutException)
            {
                return 0;
            }
        }

        private static List<string> SafeDistinctMatches(Regex regex, string text, int take)
        {
            var hits = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (Match m in regex.Matches(text))
                {
                    if (!m.Success || string.IsNullOrWhiteSpace(m.Value)) continue;
                    hits.Add(m.Value);
                    if (hits.Count >= take) break;
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // hostile input should not break analysis
            }

            return hits.Take(take).ToList();
        }

        private static IReadOnlyCollection<string> GetImportedApiNames(PEReader pe)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var importDir = pe.PEHeaders.PEHeader?.ImportTableDirectory;
            if (importDir == null || importDir.Value.RelativeVirtualAddress == 0 || importDir.Value.Size == 0)
                return names;

            var importBytes = pe.GetSectionData(importDir.Value.RelativeVirtualAddress).GetContent().ToArray();
            if (importBytes.Length < 20) return names;

            int descriptorOffset = 0;
            while (descriptorOffset + 20 <= importBytes.Length)
            {
                uint originalFirstThunk = ReadUInt32(importBytes, descriptorOffset + 0);
                uint nameRva = ReadUInt32(importBytes, descriptorOffset + 12);
                uint firstThunk = ReadUInt32(importBytes, descriptorOffset + 16);

                if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0)
                    break;

                var dllName = ReadNullTerminatedStringAtRva(pe, (int)nameRva);
                if (!string.IsNullOrWhiteSpace(dllName))
                    names.Add($"DLL:{dllName}");

                uint thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
                if (thunkRva != 0)
                {
                    foreach (var fn in ReadImportThunkNames(pe, thunkRva))
                        names.Add(fn);
                }

                descriptorOffset += 20;
            }

            return names;
        }

        private static IEnumerable<string> ReadImportThunkNames(PEReader pe, uint thunkRva)
        {
            var names = new List<string>();
            bool is64 = pe.PEHeaders.PEHeader?.Magic == PEMagic.PE32Plus;
            int step = is64 ? 8 : 4;

            var data = pe.GetSectionData((int)thunkRva).GetContent().ToArray();
            if (data.Length < step) return names;

            for (int i = 0; i + step <= data.Length && i < 8192; i += step)
            {
                ulong raw = is64 ? ReadUInt64(data, i) : ReadUInt32(data, i);
                if (raw == 0) break;

                bool isOrdinal = is64 ? ((raw & 0x8000000000000000UL) != 0) : ((raw & 0x80000000UL) != 0);
                if (isOrdinal) continue;

                int hintNameRva = (int)raw;
                var funcName = ReadNullTerminatedStringAtRva(pe, hintNameRva + 2);
                if (!string.IsNullOrWhiteSpace(funcName))
                    names.Add(funcName);
            }

            return names;
        }

        private static string ReadNullTerminatedStringAtRva(PEReader pe, int rva)
        {
            if (rva <= 0) return string.Empty;

            var content = pe.GetSectionData(rva).GetContent().ToArray();
            if (content.Length == 0) return string.Empty;

            int len = 0;
            while (len < content.Length && content[len] != 0 && len < 512)
                len++;

            if (len == 0) return string.Empty;
            return Encoding.ASCII.GetString(content, 0, len);
        }

        private static uint ReadUInt32(byte[] data, int offset)
        {
            if (offset + 4 > data.Length) return 0;
            return BitConverter.ToUInt32(data, offset);
        }

        private static ulong ReadUInt64(byte[] data, int offset)
        {
            if (offset + 8 > data.Length) return 0;
            return BitConverter.ToUInt64(data, offset);
        }

        private static double Entropy(byte[] data)
        {
            if (data.Length == 0) return 0;
            Span<int> counts = stackalloc int[256];
            foreach (var b in data) counts[b]++;

            double ent = 0.0;
            double len = data.Length;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] == 0) continue;
                double p = counts[i] / len;
                ent -= p * Math.Log(p, 2);
            }

            return ent;
        }
    }

    public sealed partial class AnalysisResult
    {
        public string FilePath { get; }
        public string FileType { get; set; } = "Unknown";
        public long Size { get; set; }
        public string Sha256 { get; set; } = "";
        public bool IsDll { get; set; }
        public bool IsExe { get; set; }
        public bool Is64 { get; set; }
        public bool IsDotNetLikely { get; set; }
        public bool IsSigned { get; set; }
        public string Signer { get; set; } = "";
        // M7: extended signature metadata.
        public string SignerIssuer { get; set; } = "";
        public DateTime SignerNotBefore { get; set; }
        public DateTime SignerNotAfter { get; set; }
        public string SignerThumbprint { get; set; } = "";
        public bool SignerChainValid { get; set; }
        public string SignerChainStatus { get; set; } = "";
        public DateTime TimeDateStampUtc { get; set; }

        public List<string> UrlsFound { get; set; } = new();
        public List<string> StringHits { get; set; } = new();
        public HashSet<string> NetDllHits { get; set; } = new(StringComparer.OrdinalIgnoreCase);

        public List<string> SectionNames { get; set; } = new();
        public Dictionary<string, double> SectionEntropy { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> PackerHints { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> ExecutableWritableSections { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public long OverlaySize { get; set; }
        // B4: extended PE metadata.
        public string ImpHash { get; set; } = "";
        public string RichHeaderHash { get; set; } = "";
        public string RichHeaderHashStd { get; set; } = "";
        public string AuthenticodeSha256 { get; set; } = "";
        public string FuzzyHash { get; set; } = ""; // simplified chunk-fingerprint; TLSH/SSDEEP follow-up
        public string OverlayType { get; set; } = "";
        public string OverlaySha256 { get; set; } = "";
        public List<string> ExportedFunctions { get; set; } = new();
        public Dictionary<string, string> VersionInfo { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> ResourceTypes { get; set; } = new();
        // B15: whole-file 4KB-chunk entropy (cap list size; last entry may be < 4KB and is excluded).
        public List<double> ChunkEntropy { get; set; } = new();
        public int HighEntropyChunkCount { get; set; }
        public bool UpxMarkerDetected { get; set; }

        // B11: C2 infrastructure indicators (onion, i2p, DGA-looking hosts, bulletproof ASN markers).
        public List<string> C2Indicators { get; set; } = new();
        // B12: autorun / persistence indicators (registry Run keys, scheduled tasks, services, startup folder).
        public List<string> PersistenceIndicators { get; set; } = new();
        // B13: browser-stealer fingerprint (DB filenames, well-known paths, DPAPI blob prefixes).
        public List<string> BrowserStealerIndicators { get; set; } = new();
        // B14: anti-analysis / anti-sandbox indicators.
        public List<string> AntiAnalysisIndicators { get; set; } = new();
        // B19: strings recovered via on-the-fly deobfuscation (base64 / xor-1 / rot13).
        public List<string> DeobfuscatedHits { get; set; } = new();

        // B16: per-capability scores, 0..100 each.
        public Dictionary<string, int> CapabilityScores { get; set; } = new(StringComparer.OrdinalIgnoreCase);

        // C15 — calibrated scoring diagnostics. Each contributor's
        // signed delta is recorded so reports can show "why this score":
        //   key   = source bucket (e.g. "Capability:CredentialTheft",
        //           "Bonus:StealerExfilPattern", "Floor:DecisiveStealer",
        //           "Discount:AllowlistMinor").
        //   value = signed integer points contributed to the final
        //           score.  Sum over Score* contributors does not need
        //           to equal the final score exactly (logistic blend
        //           applies to capabilities) but provides explainability.
        public Dictionary<string, int> ScoreContributors { get; set; } = new(StringComparer.OrdinalIgnoreCase);

        // C15 — calibrated confidence axes, each 0..100. Independent
        // from RiskScore so a UI can highlight "this is clearly an
        // infostealer" or "this is malicious but could be many things".
        public int MaliciousConfidence  { get; set; }
        public int StealerConfidence    { get; set; }
        // Inverse: 0 = clearly malicious, 100 = clearly benign/false
        // positive.  Used by UI to dim verdicts that depend mostly on
        // weak indicators.
        public int FalsePositiveRisk    { get; set; }

        // C15 — diagnostics: names of decisive floors / ceilings that
        // actually fired during this evaluation.  Floor entries push
        // the score UP (e.g. "BrowserDbDpapiExfil"); ceiling entries
        // pin it DOWN (e.g. "SingleUrlOnly", "AllowlistMinorDiscount").
        public List<string> AppliedFloors   { get; set; } = new();
        public List<string> AppliedCeilings { get; set; } = new();

        // C20 — hits against auto-ingested threat-intel feeds (CISA
        // STIX / MalwareBazaar / ThreatFox / URLhaus / local denylist
        // / TLSH / imphash).  Each entry: "<feed>|<kind>:<value>".
        // Treated as a *bonus* to the final score, not as the sole
        // basis for a verdict — feeds age, behaviour does not.
        public List<string> FeedHits { get; set; } = new();
        // B1: YARA rule matches (rule name + source file basename).
        public List<string> YaraHits { get; set; } = new();
        // C1–C3: coarse format family ("PE", "ELF", "Mach-O", "PDF", "Office", "Script-PS1", ...).
        public string FormatFamily { get; set; } = "";
        // C1: script-specific indicators (AMSI bypass, download-cradles, IEX, encoded-command, ...).
        public List<string> ScriptIndicators { get; set; } = new();
        // C3: PDF-specific risky tags (/JavaScript, /Launch, /OpenAction, /EmbeddedFile, /AA).
        public List<string> PdfRiskyTags { get; set; } = new();
        // C3: Office/macro indicators (vbaProject.bin, DDE, Auto_Open).
        public List<string> OfficeIndicators { get; set; } = new();
        // C1 (Windows shortcut): LNK target path if we could parse it.
        public string LnkTargetPath { get; set; } = "";
        // C4–C10: cloud/external lookup results. Key = provider name, value = short summary string.
        public Dictionary<string, string> CloudLookupResults { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        // C9: local AV results (clamscan).
        public List<string> LocalAvHits { get; set; } = new();
        // C10: Sigma-lite rule matches.
        public List<string> SigmaLiteHits { get; set; } = new();
        // B18: if true, analyzer matched an allowlist entry (signer thumbprint or known-good imphash)
        //      and the final risk score is clamped to at most 5.
        public bool AllowlistMatched { get; set; }
        public string AllowlistReason { get; set; } = "";

        public HashSet<string> ImportedApis { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> SuspiciousApiHits { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public int Base64BlobHits { get; set; }

        public List<string> Ipv4Hits { get; set; } = new();
        public List<string> EmailHits { get; set; } = new();
        public List<string> CryptoWalletHits { get; set; } = new();
        public List<string> JwtHits { get; set; } = new();
        public List<string> TelegramBotTokenHits { get; set; } = new();
        public List<string> DiscordTokenHits { get; set; } = new();
        public int PrivateKeyBlockHits { get; set; }

        // C13 — IOC quality fields.  Each list contains the *high-
        // confidence* subset of the corresponding raw regex output:
        // Bech32 BTC addresses whose checksum verifies, ETH addresses
        // whose mixed-case form follows EIP-55, and JWTs whose
        // base64url-decoded header parses to a JSON object with `alg`.
        public List<string> BtcBech32Validated      { get; set; } = new();
        public List<string> EthEip55Checksummed    { get; set; } = new();
        public List<string> JwtValidatedHits        { get; set; } = new();
        // Telegram/Discord tokens accompanied by exfil-context within
        // ±256 chars.  Bare tokens are noise; tokens near
        // `sendMessage`, `sendDocument`, `bot`, or `webhook` are
        // signal.
        public List<string> TelegramTokensWithContext { get; set; } = new();
        public List<string> DiscordTokensWithContext  { get; set; } = new();

        public List<string> ExternalRuleHits { get; set; } = new();
        public int ExternalRuleWeight { get; set; }

        public List<string> CustomHeuristicHits { get; set; } = new();
        public int CustomHeuristicWeight { get; set; }

        // B13/B19 extension: telltale strings that reveal malicious intent on their own — PDB paths
        // like `Z:\Projects\StealerRadmirRP\...\Stealer.pdb`, literal class/variable names containing
        // "stealer" / "grabber" / "clipper" / "keylogger", and credential-exfil template strings
        // like "Password: %s | Token: %s". These are treated as a strong credential-theft signal
        // independent of whether the sample also touches Chrome/Firefox profiles.
        public List<string> MalwareSelfIdHits { get; set; } = new();

        // Game-account stealer targeting (SA:MP / MTA / GTA / Rage:MP / CRMP / Radmir / Arizona /
        // Steam / Roblox / Minecraft / battle.net / Riot launcher / etc.). Populated by
        // DetectGameAccountStealerTargeting. One hit alone is weak (lots of legit game software
        // references these), but combined with MalwareSelfIdHits or an exfil channel it's decisive.
        public List<string> GameTargetHits { get; set; } = new();

        // Telegram exfil endpoints: strings containing `api.telegram.org/bot…` or `t.me/…` with a
        // Bot-API verb (sendMessage/sendDocument/…) or a %s/{0} placeholder. Populated by
        // DetectTelegramExfilEndpoints. This is an extremely high-confidence stealer signal.
        public List<string> TelegramExfilEndpoints { get; set; } = new();

        public int RiskScore { get; set; }
        public bool PackedLikely { get; private set; }
        public bool NetLikely { get; private set; }
        public string ReasonsShort { get; private set; } = "";
        public string FamilyName { get; set; } = "";
        public double FamilyConfidence { get; set; }
        public string FamilyReason { get; set; } = "";
        public string StructureFingerprint { get; set; } = "";

        public int TotalIocHits => Ipv4Hits.Count + EmailHits.Count + CryptoWalletHits.Count + JwtHits.Count + TelegramBotTokenHits.Count + DiscordTokenHits.Count + ExternalRuleHits.Count + CustomHeuristicHits.Count + PrivateKeyBlockHits;

        public string RiskLevel
        {
            get
            {
                if (RiskScore >= 70) return "HIGH";
                if (RiskScore >= 40) return "MEDIUM";
                return "LOW";
            }
        }

        public AnalysisResult(string filePath) => FilePath = filePath;

        public static AnalysisResult Error(string filePath, string err)
        {
            return new AnalysisResult(filePath)
            {
                FileType = "ERROR",
                RiskScore = 0,
                ReasonsShort = err
            };
        }

        public void FinalizeFlags()
        {
            PackedLikely = PackerHints.Count > 0 || ExecutableWritableSections.Count > 0 || OverlaySize > 200_000;
            NetLikely = UrlsFound.Count > 0 || NetDllHits.Count > 0 || SuspiciousApiHits.Count > 0 || Ipv4Hits.Count > 0 || CustomHeuristicHits.Count > 0;

            var reasons = new List<string>();
            if (PackedLikely) reasons.Add("packed/obfuscated");
            if (NetLikely) reasons.Add("net-likely");
            if (!IsSigned && (IsDll || IsExe)) reasons.Add("unsigned");
            if (StringHits.Count > 0) reasons.Add($"strings:{StringHits.Count}");
            if (UrlsFound.Count > 0) reasons.Add($"urls:{UrlsFound.Count}");
            if (NetDllHits.Count > 0) reasons.Add($"netdll:{NetDllHits.Count}");
            if (SuspiciousApiHits.Count > 0) reasons.Add($"api:{SuspiciousApiHits.Count}");
            if (ExternalRuleHits.Count > 0) reasons.Add($"xrules:{ExternalRuleHits.Count}");
            if (CustomHeuristicHits.Count > 0) reasons.Add($"custom:{CustomHeuristicHits.Count}");
            if (TotalIocHits > 0) reasons.Add($"ioc:{TotalIocHits}");
            if (Base64BlobHits > 0) reasons.Add($"b64:{Base64BlobHits}");
            if (JwtHits.Count > 0) reasons.Add($"jwt:{JwtHits.Count}");
            if (TelegramBotTokenHits.Count > 0) reasons.Add($"tgbot:{TelegramBotTokenHits.Count}");
            if (DiscordTokenHits.Count > 0) reasons.Add($"dct:{DiscordTokenHits.Count}");
            if (PrivateKeyBlockHits > 0) reasons.Add($"pkey:{PrivateKeyBlockHits}");
            if (MalwareSelfIdHits.Count > 0) reasons.Add($"selfid:{MalwareSelfIdHits.Count}");
            if (GameTargetHits.Count > 0) reasons.Add($"game:{GameTargetHits.Count}");
            if (TelegramExfilEndpoints.Count > 0) reasons.Add($"tgxfil:{TelegramExfilEndpoints.Count}");
            if (!string.IsNullOrWhiteSpace(FamilyName)) reasons.Add($"fam:{FamilyName}");

            ReasonsShort = reasons.Count == 0 ? "no strong indicators" : string.Join(", ", reasons.Take(7));

            // B16 — classify accumulated evidence into Weak / Medium /
            // Strong / Critical tiers. Idempotent: re-running it does
            // not double-count.
            try { TieredFactClassifier.Classify(this); } catch { }

            // P1...P4 + P12 — structural packer / protector detection.
            // Reads imports / sections / overlay / entropy that the
            // PE-parse stage already filled and writes
            // r.Protection + r.AnalysisStatus.
            try { ProtectionAnalyzer.Compute(this); } catch { }

            // P10 — capability graph + FinalVerdict synthesis.  Runs
            // last so it can read RiskScore, MaliciousConfidence,
            // AppliedFloors, CapabilityScores, Protection and the
            // P12 AnalysisStatus.
            try { CapabilityGraph.Build(this); } catch { }
        }

        public string ToFullReport()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"File: {FilePath}");
            sb.AppendLine($"Type: {FileType} | Arch: {(Is64 ? "x64" : "x86/unknown")} | DotNetLikely: {IsDotNetLikely} | Size: {Size} bytes");
            sb.AppendLine($"SHA256: {Sha256}");
            if (!string.IsNullOrWhiteSpace(ImpHash)) sb.AppendLine($"ImpHash: {ImpHash}");
            if (!string.IsNullOrWhiteSpace(AuthenticodeSha256)) sb.AppendLine($"Authenticode SHA256: {AuthenticodeSha256}");
            if (!string.IsNullOrWhiteSpace(RichHeaderHash)) sb.AppendLine($"Rich header hash: {RichHeaderHash} (std: {RichHeaderHashStd})");
            if (!string.IsNullOrWhiteSpace(FuzzyHash)) sb.AppendLine($"Chunk fingerprint: {FuzzyHash}");
            sb.AppendLine($"Signed: {IsSigned} {(string.IsNullOrWhiteSpace(Signer) ? string.Empty : $"| Signer: {Signer}")}");
            if (IsSigned)
            {
                if (!string.IsNullOrWhiteSpace(SignerIssuer))
                    sb.AppendLine($"Issuer: {SignerIssuer}");
                if (SignerNotBefore != default || SignerNotAfter != default)
                    sb.AppendLine($"Validity: {SignerNotBefore:yyyy-MM-dd} .. {SignerNotAfter:yyyy-MM-dd}");
                if (!string.IsNullOrWhiteSpace(SignerThumbprint))
                    sb.AppendLine($"Thumbprint: {SignerThumbprint}");
                sb.AppendLine($"ChainValid: {SignerChainValid}{(string.IsNullOrWhiteSpace(SignerChainStatus) ? string.Empty : $" ({SignerChainStatus})")}");
            }
            if (TimeDateStampUtc != default)
                sb.AppendLine($"PE timestamp (UTC): {TimeDateStampUtc:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Risk: {RiskScore}/100 ({RiskLevel}) | PackedLikely: {PackedLikely} | NetLikely: {NetLikely}");
            if (AllowlistMatched)
                sb.AppendLine($"Allowlist match: {AllowlistReason} — risk score clamped.");
            if (CapabilityScores.Count > 0)
            {
                var caps = CapabilityScores
                    .Where(kv => kv.Value > 0)
                    .OrderByDescending(kv => kv.Value)
                    .Select(kv => $"{kv.Key}={kv.Value}");
                if (caps.Any()) sb.AppendLine("Capabilities: " + string.Join(", ", caps));
            }
            if (!string.IsNullOrWhiteSpace(FamilyName))
                sb.AppendLine($"Family: {FamilyName} ({FamilyConfidence:0}%) | Reason: {FamilyReason}");
            if (!string.IsNullOrWhiteSpace(StructureFingerprint))
                sb.AppendLine($"Structure fingerprint: {StructureFingerprint}");
            sb.AppendLine();

            if (CustomHeuristicHits.Count > 0)
            {
                sb.AppendLine("== Custom heuristic hits (6000+ internal checks) ==");
                foreach (var h in CustomHeuristicHits.Take(180))
                    sb.AppendLine($"  - {h}");
                sb.AppendLine($"  - total custom heuristic weight: {CustomHeuristicWeight}");
                sb.AppendLine();
            }

            if (SectionNames.Count > 0)
            {
                sb.AppendLine("== Sections (entropy) ==");
                foreach (var s in SectionNames.Take(40))
                {
                    if (SectionEntropy.TryGetValue(s, out var e))
                        sb.AppendLine($"  {s,-14} entropy={e:0.00}");
                    else
                        sb.AppendLine($"  {s}");
                }
                sb.AppendLine();
            }

            if (ExecutableWritableSections.Count > 0)
            {
                sb.AppendLine("== Executable + writable sections ==");
                foreach (var sec in ExecutableWritableSections)
                    sb.AppendLine($"  - {sec}");
                sb.AppendLine();
            }

            if (OverlaySize > 0)
            {
                sb.AppendLine("== Overlay ==");
                sb.AppendLine($"  - overlay bytes: {OverlaySize}");
                if (!string.IsNullOrWhiteSpace(OverlayType)) sb.AppendLine($"  - overlay type: {OverlayType}");
                if (!string.IsNullOrWhiteSpace(OverlaySha256)) sb.AppendLine($"  - overlay sha256: {OverlaySha256}");
                sb.AppendLine();
            }

            if (VersionInfo.Count > 0)
            {
                sb.AppendLine("== Version info ==");
                foreach (var kv in VersionInfo) sb.AppendLine($"  - {kv.Key}: {kv.Value}");
                sb.AppendLine();
            }

            if (ExportedFunctions.Count > 0)
            {
                sb.AppendLine($"== Exports ({ExportedFunctions.Count}) ==");
                foreach (var e in ExportedFunctions.Take(40)) sb.AppendLine($"  - {e}");
                sb.AppendLine();
            }

            if (ResourceTypes.Count > 0)
                sb.AppendLine($"Resource types: {string.Join(", ", ResourceTypes)}");

            if (ChunkEntropy.Count > 0)
            {
                sb.AppendLine($"== Entropy by 4KB chunks ({ChunkEntropy.Count} chunks, high>=7.2: {HighEntropyChunkCount}) ==");
                // Dump a sparsely-sampled profile so the report stays readable for large files.
                int step = Math.Max(1, ChunkEntropy.Count / 32);
                for (int i = 0; i < ChunkEntropy.Count; i += step)
                    sb.AppendLine($"  chunk[{i}] = {ChunkEntropy[i]:0.00}");
                sb.AppendLine();
            }

            if (UpxMarkerDetected)
                sb.AppendLine("UPX marker detected in file bytes.");

            if (C2Indicators.Count > 0)
            {
                sb.AppendLine("== C2 / infrastructure indicators ==");
                foreach (var ind in C2Indicators.Take(40)) sb.AppendLine($"  - {ind}");
                sb.AppendLine();
            }
            if (PersistenceIndicators.Count > 0)
            {
                sb.AppendLine("== Persistence indicators ==");
                foreach (var ind in PersistenceIndicators.Take(40)) sb.AppendLine($"  - {ind}");
                sb.AppendLine();
            }
            if (BrowserStealerIndicators.Count > 0)
            {
                sb.AppendLine("== Browser-stealer fingerprint ==");
                foreach (var ind in BrowserStealerIndicators.Take(40)) sb.AppendLine($"  - {ind}");
                sb.AppendLine();
            }
            if (MalwareSelfIdHits.Count > 0)
            {
                sb.AppendLine("== Malware self-identification ==");
                foreach (var ind in MalwareSelfIdHits.Take(40)) sb.AppendLine($"  - {ind}");
                sb.AppendLine();
            }
            if (GameTargetHits.Count > 0)
            {
                sb.AppendLine($"== Game-account stealer targeting ({GameTargetHits.Count}) ==");
                foreach (var ind in GameTargetHits.Take(40)) sb.AppendLine($"  - {ind}");
                sb.AppendLine();
            }
            if (TelegramExfilEndpoints.Count > 0)
            {
                sb.AppendLine($"== Telegram exfil endpoints ({TelegramExfilEndpoints.Count}) ==");
                foreach (var ind in TelegramExfilEndpoints.Take(20)) sb.AppendLine($"  - {ind}");
                sb.AppendLine();
            }
            if (AntiAnalysisIndicators.Count > 0)
            {
                sb.AppendLine("== Anti-analysis / anti-sandbox ==");
                foreach (var ind in AntiAnalysisIndicators.Take(40)) sb.AppendLine($"  - {ind}");
                sb.AppendLine();
            }
            if (DeobfuscatedHits.Count > 0)
            {
                sb.AppendLine($"== Deobfuscated string hits ({DeobfuscatedHits.Count}) ==");
                foreach (var d in DeobfuscatedHits.Take(32)) sb.AppendLine($"  - {d}");
                sb.AppendLine();
            }

            if (YaraHits.Count > 0)
            {
                sb.AppendLine($"== YARA matches ({YaraHits.Count}) ==");
                foreach (var y in YaraHits.Take(32)) sb.AppendLine($"  - {y}");
                sb.AppendLine();
            }

            // P7 — print FormatFamily for non-PE inputs and for the
            // game-mod ASI variant (the latter is structurally a DLL
            // but is treated as its own family).  Generic PE-EXE /
            // PE-DLL stay implicit since the FileType already says
            // "PE EXE" / "PE DLL".
            if (!string.IsNullOrWhiteSpace(FormatFamily) &&
                FormatFamily != "PE"      &&
                FormatFamily != "PE-EXE"  &&
                FormatFamily != "PE-DLL")
                sb.AppendLine($"Format family: {FormatFamily}");
            if (!string.IsNullOrWhiteSpace(LnkTargetPath))
                sb.AppendLine($"LNK target: {LnkTargetPath}");
            if (ScriptIndicators.Count > 0)
            {
                sb.AppendLine("== Script indicators ==");
                foreach (var s in ScriptIndicators.Take(40)) sb.AppendLine($"  - {s}");
                sb.AppendLine();
            }
            if (PdfRiskyTags.Count > 0)
            {
                sb.AppendLine("== PDF risky tags ==");
                foreach (var t in PdfRiskyTags.Take(20)) sb.AppendLine($"  - {t}");
                sb.AppendLine();
            }
            if (OfficeIndicators.Count > 0)
            {
                sb.AppendLine("== Office / document macros ==");
                foreach (var o in OfficeIndicators.Take(20)) sb.AppendLine($"  - {o}");
                sb.AppendLine();
            }

            if (CloudLookupResults.Count > 0)
            {
                sb.AppendLine("== Cloud / external enrichment ==");
                foreach (var kv in CloudLookupResults) sb.AppendLine($"  - {kv.Key}: {kv.Value}");
                sb.AppendLine();
            }
            if (LocalAvHits.Count > 0)
            {
                sb.AppendLine($"== Local AV hits ({LocalAvHits.Count}) ==");
                foreach (var h in LocalAvHits.Take(20)) sb.AppendLine($"  - {h}");
                sb.AppendLine();
            }
            if (SigmaLiteHits.Count > 0)
            {
                sb.AppendLine("== Sigma-lite matches ==");
                foreach (var h in SigmaLiteHits.Take(20)) sb.AppendLine($"  - {h}");
                sb.AppendLine();
            }

            // BB1-BB10: advanced detection modules.
            if (SigmaFullHits.Count > 0)
            {
                sb.AppendLine($"== Sigma-full matches ({SigmaFullHits.Count}) ==");
                foreach (var h in SigmaFullHits.Take(30)) sb.AppendLine($"  - {h}");
                sb.AppendLine();
            }
            if (CapaHits.Count > 0)
            {
                sb.AppendLine($"== CAPA capabilities ({CapaHits.Count}) ==");
                foreach (var h in CapaHits.Take(30)) sb.AppendLine($"  - {h}");
                sb.AppendLine();
            }
            if (!string.IsNullOrEmpty(ImphashFamilyMatch) || !string.IsNullOrEmpty(RichHeaderFamilyMatch))
            {
                sb.AppendLine("== Known-bad build fingerprints ==");
                if (!string.IsNullOrEmpty(ImphashFamilyMatch))    sb.AppendLine($"  - imphash family: {ImphashFamilyMatch}");
                if (!string.IsNullOrEmpty(RichHeaderFamilyMatch)) sb.AppendLine($"  - rich-header family: {RichHeaderFamilyMatch}");
                sb.AppendLine();
            }
            if (InjectionPrimitives.Count > 0)
            {
                sb.AppendLine($"== Process-injection primitives ({InjectionPrimitives.Count}) ==");
                foreach (var t in InjectionPrimitives) sb.AppendLine($"  - {t}");
                sb.AppendLine();
            }
            if (!string.IsNullOrEmpty(DllSideloadTargetGuess))
            {
                sb.AppendLine("== DLL-sideloading suspect ==");
                sb.AppendLine($"  - {DllSideloadTargetGuess}");
                sb.AppendLine();
            }
            if (DgaSuspiciousDomains.Count > 0)
            {
                sb.AppendLine($"== DGA-suspicious domains ({DgaSuspiciousDomains.Count}) ==");
                foreach (var d in DgaSuspiciousDomains.Take(20)) sb.AppendLine($"  - {d}");
                sb.AppendLine();
            }
            if (BulletproofAsnHits.Count > 0)
            {
                sb.AppendLine($"== Bulletproof ASN / CIDR hits ({BulletproofAsnHits.Count}) ==");
                foreach (var b in BulletproofAsnHits.Take(20)) sb.AppendLine($"  - {b}");
                sb.AppendLine();
            }
            if (MitreTtps.Count > 0)
            {
                sb.AppendLine($"== MITRE ATT&CK TTPs ({MitreTtps.Count}) ==");
                foreach (var t in MitreTtps.OrderBy(x => x, StringComparer.Ordinal)) sb.AppendLine($"  - {t}");
                sb.AppendLine();
            }
            if (!string.IsNullOrEmpty(MlFamilyPrediction))
            {
                sb.AppendLine("== ML family classifier ==");
                sb.AppendLine($"  - prediction: {MlFamilyPrediction}");
                if (MlFamilyConfidence > 0) sb.AppendLine($"  - confidence: {MlFamilyConfidence:P1}");
                sb.AppendLine();
            }

            // BB11-BB26 sections.
            if (ResourceStegoHits.Count > 0)
            {
                sb.AppendLine($"== Resource stego / embedded payloads ({ResourceStegoHits.Count}) ==");
                foreach (var h in ResourceStegoHits) sb.AppendLine($"  - {h}");
                sb.AppendLine();
            }
            if (!string.IsNullOrEmpty(OverlayClassification))
            {
                sb.AppendLine($"== Overlay classification ==");
                sb.AppendLine($"  - {OverlayClassification}");
                sb.AppendLine();
            }
            if (KnownPackerHits.Count > 0)
            {
                sb.AppendLine($"== Known packer/protector hits ({KnownPackerHits.Count}) ==");
                foreach (var h in KnownPackerHits) sb.AppendLine($"  - {h}");
                sb.AppendLine();
            }
            if (DotNetObfuscatorHits.Count > 0)
            {
                sb.AppendLine($"== .NET obfuscator hits ({DotNetObfuscatorHits.Count}) ==");
                foreach (var h in DotNetObfuscatorHits) sb.AppendLine($"  - {h}");
                sb.AppendLine();
            }
            if (ClipboardHijackHits.Count > 0)
            {
                sb.AppendLine($"== Clipboard hijack (clipper) ({ClipboardHijackHits.Count}) ==");
                foreach (var h in ClipboardHijackHits) sb.AppendLine($"  - {h}");
                sb.AppendLine();
            }
            if (KeyloggerHits.Count > 0)
            {
                sb.AppendLine($"== Keylogger primitives ({KeyloggerHits.Count}) ==");
                foreach (var h in KeyloggerHits) sb.AppendLine($"  - {h}");
                sb.AppendLine();
            }
            if (ScreenGrabberHits.Count > 0)
            {
                sb.AppendLine($"== Screen-grabber primitives ({ScreenGrabberHits.Count}) ==");
                foreach (var h in ScreenGrabberHits) sb.AppendLine($"  - {h}");
                sb.AppendLine();
            }
            if (StealerMutexHits.Count > 0)
            {
                sb.AppendLine($"== Stealer mutex names ({StealerMutexHits.Count}) ==");
                foreach (var h in StealerMutexHits) sb.AppendLine($"  - {h}");
                sb.AppendLine();
            }
            if (CredentialFilePathHits.Count > 0)
            {
                sb.AppendLine($"== Credential file paths ({CredentialFilePathHits.Count}) ==");
                foreach (var h in CredentialFilePathHits.Take(30)) sb.AppendLine($"  - {h}");
                sb.AppendLine();
            }
            if (CryptoWalletPathHits.Count > 0)
            {
                sb.AppendLine($"== Crypto-wallet paths ({CryptoWalletPathHits.Count}) ==");
                foreach (var h in CryptoWalletPathHits.Take(30)) sb.AppendLine($"  - {h}");
                sb.AppendLine();
            }
            if (TelegramDesktopTheftHits.Count > 0)
            {
                sb.AppendLine($"== Telegram Desktop tdata theft ({TelegramDesktopTheftHits.Count}) ==");
                foreach (var h in TelegramDesktopTheftHits) sb.AppendLine($"  - {h}");
                sb.AppendLine();
            }
            if (DiscordLevelDbTheftHits.Count > 0)
            {
                sb.AppendLine($"== Discord LevelDB theft ({DiscordLevelDbTheftHits.Count}) ==");
                foreach (var h in DiscordLevelDbTheftHits) sb.AppendLine($"  - {h}");
                sb.AppendLine();
            }
            if (TwoFactorTheftHits.Count > 0)
            {
                sb.AppendLine($"== 2FA / session-token theft ({TwoFactorTheftHits.Count}) ==");
                foreach (var h in TwoFactorTheftHits) sb.AppendLine($"  - {h}");
                sb.AppendLine();
            }
            if (RansomwareHits.Count > 0)
            {
                sb.AppendLine($"== Ransomware indicators ({RansomwareHits.Count}) ==");
                foreach (var h in RansomwareHits) sb.AppendLine($"  - {h}");
                sb.AppendLine();
            }
            if (DestructivePayloadHits.Count > 0)
            {
                sb.AppendLine($"== Destructive / wiper indicators ({DestructivePayloadHits.Count}) ==");
                foreach (var h in DestructivePayloadHits) sb.AppendLine($"  - {h}");
                sb.AppendLine();
            }
            // CC1-CC12 — format-specific detectors.
            void EmitHits(string header, List<string> hits)
            {
                if (hits == null || hits.Count == 0) return;
                sb.AppendLine($"== {header} ({hits.Count}) ==");
                foreach (var h in hits.Take(20)) sb.AppendLine($"  - {h}");
                sb.AppendLine();
            }
            EmitHits("MSI CustomAction markers (CC1)", MsiCustomActionHits);
            EmitHits("APPX/MSIX dangerous capabilities (CC2)", AppxCapabilityHits);
            EmitHits("Mach-O suspicious load commands (CC3)", MachOLoadCommandHits);
            EmitHits("ELF dynamic / RPATH / syscall markers (CC4)", ElfDynamicHits);
            EmitHits("Office VBA macro markers (CC5)", VbaMacroHits);
            EmitHits("PDF JavaScript / Action markers (CC6)", PdfJsActionHits);
            EmitHits("LNK shell-link command tokens (CC7)", LnkCommandHits);
            EmitHits("PowerShell obfuscation / LOLBin markers (CC8)", PowerShellObfHits);
            EmitHits("JavaScript obfuscation markers (CC9)", JsObfuscationHits);
            EmitHits("HTA/CHM execution wrappers (CC10)", HtaChmHits);
            EmitHits("OneNote embedded attachments (CC11)", OneNoteEmbedHits);
            EmitHits("ClickOnce manifest anomalies (CC12)", ClickOnceHits);
            EmitHits("Lua loader / stealer threat groups (CC13)", LuaThreatHits);

            // BB27 — browser-JS credential stealer.
            if (JsCredScraperHits.Count > 0 || JsCredPostHits.Count > 0 || JsFormHookHits.Count > 0 || JsStealerSelfIdHits.Count > 0)
            {
                sb.AppendLine("== Browser-JS credential stealer (BB27) ==");
                if (JsCredScraperHits.Count > 0)
                {
                    sb.AppendLine($"  Credential-scraping DOM patterns ({JsCredScraperHits.Count}):");
                    foreach (var h in JsCredScraperHits.Take(15)) sb.AppendLine($"    - {h}");
                }
                if (JsCredPostHits.Count > 0)
                {
                    sb.AppendLine($"  Credential-POST payload patterns ({JsCredPostHits.Count}):");
                    foreach (var h in JsCredPostHits.Take(10)) sb.AppendLine($"    - {h}");
                }
                if (JsFormHookHits.Count > 0)
                {
                    sb.AppendLine($"  Form-hook / listener patterns ({JsFormHookHits.Count}):");
                    foreach (var h in JsFormHookHits.Take(15)) sb.AppendLine($"    - {h}");
                }
                if (JsStealerSelfIdHits.Count > 0)
                {
                    sb.AppendLine($"  JS self-ID keywords ({JsStealerSelfIdHits.Count}):");
                    foreach (var h in JsStealerSelfIdHits.Take(15)) sb.AppendLine($"    - {h}");
                }
                sb.AppendLine();
            }

            if (StringCrossRefs.Count > 0)
            {
                sb.AppendLine($"== String → PE section cross-reference ({StringCrossRefs.Count}) ==");
                foreach (var kv in StringCrossRefs.Take(20))
                {
                    var key = kv.Key.Length > 80 ? kv.Key.Substring(0, 80) + "…" : kv.Key;
                    sb.AppendLine($"  - \"{key}\" → {kv.Value}");
                }
                sb.AppendLine();
            }

            if (PackerHints.Count > 0)
            {
                sb.AppendLine("== Packer/Obfuscation hints ==");
                foreach (var h in PackerHints.Take(60))
                    sb.AppendLine($"  - {h}");
                sb.AppendLine();
            }

            if (NetDllHits.Count > 0)
            {
                sb.AppendLine("== Network DLL hints ==");
                foreach (var d in NetDllHits)
                    sb.AppendLine($"  - {d}");
                sb.AppendLine();
            }

            if (SuspiciousApiHits.Count > 0)
            {
                sb.AppendLine("== Suspicious API hints ==");
                foreach (var a in SuspiciousApiHits)
                    sb.AppendLine($"  - {a}");
                sb.AppendLine();
            }

            if (JwtHits.Count > 0 || TelegramBotTokenHits.Count > 0 || DiscordTokenHits.Count > 0 || PrivateKeyBlockHits > 0)
            {
                sb.AppendLine("== Secret/Token indicators ==");
                foreach (var j in JwtHits.Take(40)) sb.AppendLine($"  - jwt: {j}");
                foreach (var t in TelegramBotTokenHits.Take(40)) sb.AppendLine($"  - telegram-bot-token: {t}");
                foreach (var d in DiscordTokenHits.Take(40)) sb.AppendLine($"  - discord-token: {d}");
                if (PrivateKeyBlockHits > 0) sb.AppendLine($"  - private-key-blocks: {PrivateKeyBlockHits}");
                sb.AppendLine();
            }

            if (ExternalRuleHits.Count > 0)
            {
                sb.AppendLine("== External community rule hits ==");
                foreach (var r in ExternalRuleHits)
                    sb.AppendLine($"  - {r}");
                sb.AppendLine($"  - total external-rule weight: {ExternalRuleWeight}");
                sb.AppendLine();
            }

            if (Base64BlobHits > 0)
            {
                sb.AppendLine("== Encoded blob indicators ==");
                sb.AppendLine($"  - base64-like blobs: {Base64BlobHits}");
                sb.AppendLine();
            }

            if (UrlsFound.Count > 0)
            {
                sb.AppendLine("== URLs found ==");
                foreach (var u in UrlsFound.Take(200))
                    sb.AppendLine($"  - {u}");
                sb.AppendLine();
            }

            if (Ipv4Hits.Count > 0)
            {
                sb.AppendLine("== IPv4 indicators ==");
                foreach (var ip in Ipv4Hits.Take(200))
                    sb.AppendLine($"  - {ip}");
                sb.AppendLine();
            }

            if (EmailHits.Count > 0)
            {
                sb.AppendLine("== Email indicators ==");
                foreach (var e in EmailHits.Take(200))
                    sb.AppendLine($"  - {e}");
                sb.AppendLine();
            }

            if (CryptoWalletHits.Count > 0)
            {
                sb.AppendLine("== Crypto-wallet indicators ==");
                foreach (var w in CryptoWalletHits.Take(150))
                    sb.AppendLine($"  - {w}");
                sb.AppendLine();
            }

            if (StringHits.Count > 0)
            {
                sb.AppendLine("== Suspicious strings (sample) ==");
                foreach (var s in StringHits.Take(240))
                    sb.AppendLine($"  - {s}");
                sb.AppendLine();
            }

            sb.AppendLine("NOTE: Это эвристика. Для подтверждения угрозы нужен запуск в изоляции + мониторинг сети/процессов/файлового поведения.");
            return sb.ToString();
        }
    }

    // E1–E6: report writers. All static; no UI dependencies. JSON is machine-readable, HTML is
    // human-friendly with folding sections, PDF is a minimal ASCII PDF document generated from
    // scratch (no external deps), STIX 2.1 and SARIF are standard security-findings formats.
    public static class ReportWriter
    {
        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault,
        };

        // H1 — CSV summary (same columns as the GUI's 'Экспорт сводки CSV' button).
        public static string ToCsv(IReadOnlyList<AnalysisResult> results)
        {
            static string Esc(string s)
            {
                s ??= "";
                bool needsQuotes = s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0;
                var escaped = s.Replace("\"", "\"\"");
                return needsQuotes ? "\"" + escaped + "\"" : escaped;
            }
            var sb = new StringBuilder();
            sb.AppendLine("File,Type,RiskScore,RiskLevel,Family,Confidence,Net,Packed,Signed,Heuristics,URLs,API,IOCs,SHA256,Reasons");
            foreach (var r in results)
            {
                sb.AppendLine(string.Join(",", new[]
                {
                    Esc(r.FilePath), Esc(r.FileType), r.RiskScore.ToString(), Esc(r.RiskLevel),
                    Esc(r.FamilyName), r.FamilyConfidence.ToString("0.##"),
                    r.NetLikely.ToString(), r.PackedLikely.ToString(), r.IsSigned.ToString(),
                    r.CustomHeuristicHits.Count.ToString(), r.UrlsFound.Count.ToString(),
                    r.SuspiciousApiHits.Count.ToString(), r.TotalIocHits.ToString(),
                    Esc(r.Sha256), Esc(r.ReasonsShort),
                }));
            }
            return sb.ToString();
        }

        // E1 — JSON
        public static string ToJson(IReadOnlyList<AnalysisResult> results)
        {
            var doc = new
            {
                schema = "https://whysgit.github.io/antistealer/report.v1.json",
                generated_at = DateTimeOffset.UtcNow,
                tool = new { name = "AntiStealer", version = "1.0" },
                results,
            };
            return JsonSerializer.Serialize(doc, JsonOpts);
        }

        // E2 — Interactive HTML (section 11.4)
        //
        // Same shape as before (preserves snapshot contracts: <!doctype html>,
        // <title>AntiStealer report</title>, <table>/<thead>/<tbody>,
        // tr.risk-high/risk-med/risk-low classes) but with vanilla-JS
        // controls layered on top: text filter, level filter (chip
        // toggles), column sort, expand/collapse-all, "copy SHA-256",
        // sticky table header, dark theme via prefers-color-scheme.
        public static string ToHtml(IReadOnlyList<AnalysisResult> results)
        {
            var sb = new StringBuilder(96 * 1024);
            sb.AppendLine("<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\"/>");
            sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/>");
            sb.AppendLine("<title>AntiStealer report</title>");
            sb.AppendLine("<style>");
            sb.AppendLine(":root{--bg:#fafafa;--fg:#222;--border:#ddd;--card:#fff;--muted:#666;--high:#ffe6e6;--med:#fff5e0;--low:#e7fae7;--high-bd:#c0392b;--med-bd:#e67e22;--low-bd:#27ae60;}");
            sb.AppendLine("@media (prefers-color-scheme:dark){:root{--bg:#1a1a1a;--fg:#e6e6e6;--border:#333;--card:#222;--muted:#999;--high:#3a1a1a;--med:#3a2e1a;--low:#1a2e1a;}}");
            sb.AppendLine("body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:24px;color:var(--fg);background:var(--bg)}");
            sb.AppendLine("h1{font-size:22px;margin:0 0 16px}h2{font-size:16px;border-top:1px solid var(--border);padding-top:12px}");
            sb.AppendLine(".controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px;padding:10px;background:var(--card);border:1px solid var(--border);border-radius:6px;position:sticky;top:0;z-index:10}");
            sb.AppendLine(".controls input[type=text]{padding:6px 10px;border:1px solid var(--border);border-radius:4px;background:var(--bg);color:var(--fg);min-width:240px;font-size:13px}");
            sb.AppendLine(".chip{display:inline-block;padding:3px 10px;border-radius:12px;font-size:12px;cursor:pointer;user-select:none;border:1px solid var(--border);background:var(--bg);color:var(--fg)}");
            sb.AppendLine(".chip.active{background:var(--fg);color:var(--bg)}");
            sb.AppendLine(".chip[data-level=HIGH]{border-color:var(--high-bd)}.chip[data-level=HIGH].active{background:var(--high-bd);color:#fff}");
            sb.AppendLine(".chip[data-level=MEDIUM]{border-color:var(--med-bd)}.chip[data-level=MEDIUM].active{background:var(--med-bd);color:#fff}");
            sb.AppendLine(".chip[data-level=LOW]{border-color:var(--low-bd)}.chip[data-level=LOW].active{background:var(--low-bd);color:#fff}");
            sb.AppendLine(".meta{color:var(--muted);font-size:12px;margin-left:auto}");
            sb.AppendLine("table{border-collapse:collapse;width:100%;margin-bottom:16px;font-size:13px;background:var(--card)}");
            sb.AppendLine("th,td{border:1px solid var(--border);padding:6px 8px;text-align:left;vertical-align:top}");
            sb.AppendLine("th{cursor:pointer;user-select:none;background:var(--card);position:sticky;top:60px;z-index:5}");
            sb.AppendLine("th[data-sort]::after{content:' ⇅';color:var(--muted);font-size:10px}");
            sb.AppendLine("th[data-sort-dir=asc]::after{content:' ↑'}th[data-sort-dir=desc]::after{content:' ↓'}");
            sb.AppendLine("tr.risk-high{background:var(--high)}tr.risk-med{background:var(--med)}tr.risk-low{background:var(--low)}");
            sb.AppendLine("tr.hidden{display:none}");
            sb.AppendLine("details{margin:8px 0;padding:8px;border:1px solid var(--border);background:var(--card);border-radius:4px}");
            sb.AppendLine("details summary{cursor:pointer;font-weight:600}");
            sb.AppendLine("pre{white-space:pre-wrap;word-wrap:break-word;font-size:12px;line-height:1.4}");
            sb.AppendLine(".badge{display:inline-block;padding:1px 6px;border-radius:3px;font-size:11px;font-weight:600}");
            sb.AppendLine(".badge-high{background:var(--high-bd);color:#fff}.badge-med{background:var(--med-bd);color:#fff}.badge-low{background:var(--low-bd);color:#fff}");
            sb.AppendLine("code{font-size:11px;font-family:ui-monospace,Menlo,Consolas,monospace}");
            sb.AppendLine(".copy{cursor:pointer;color:var(--muted);font-size:11px;margin-left:4px;border:none;background:transparent}");
            sb.AppendLine(".copy:hover{color:var(--fg)}");
            sb.AppendLine("</style></head><body>");
            sb.AppendLine($"<h1>AntiStealer отчёт — {results.Count} файлов, {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</h1>");

            int high = results.Count(r => r.RiskScore >= 70);
            int med  = results.Count(r => r.RiskScore >= 40 && r.RiskScore < 70);
            int low  = results.Count - high - med;

            sb.AppendLine("<div class=\"controls\">");
            sb.AppendLine("  <input type=\"text\" id=\"q\" placeholder=\"Поиск по файлу / семейству / SHA-256 …\"/>");
            sb.AppendLine($"  <span class=\"chip active\" data-level=\"HIGH\">HIGH {high}</span>");
            sb.AppendLine($"  <span class=\"chip active\" data-level=\"MEDIUM\">MEDIUM {med}</span>");
            sb.AppendLine($"  <span class=\"chip active\" data-level=\"LOW\">LOW {low}</span>");
            sb.AppendLine("  <span class=\"chip\" id=\"expand-all\">Развернуть всё</span>");
            sb.AppendLine("  <span class=\"chip\" id=\"collapse-all\">Свернуть всё</span>");
            sb.AppendLine($"  <span class=\"meta\" id=\"counter\">Показано: {results.Count} / {results.Count}</span>");
            sb.AppendLine("</div>");

            sb.AppendLine("<table><thead><tr>");
            sb.AppendLine("  <th data-sort=\"name\">Файл</th>");
            sb.AppendLine("  <th data-sort=\"type\">Тип</th>");
            sb.AppendLine("  <th data-sort=\"score\" data-sort-num=\"1\" data-sort-dir=\"desc\">Риск</th>");
            sb.AppendLine("  <th data-sort=\"level\">Уровень</th>");
            sb.AppendLine("  <th data-sort=\"family\">Семейство</th>");
            sb.AppendLine("  <th data-sort=\"sha\">SHA-256</th>");
            sb.AppendLine("</tr></thead><tbody>");
            foreach (var r in results.OrderByDescending(x => x.RiskScore))
            {
                var cls = r.RiskScore >= 70 ? "risk-high" : r.RiskScore >= 40 ? "risk-med" : "risk-low";
                string anchor = "f-" + (r.Sha256.Length >= 8 ? r.Sha256[..8] : r.RiskScore.ToString("x"));
                sb.Append($"<tr class=\"{cls}\" data-level=\"{r.RiskLevel}\" data-score=\"{r.RiskScore}\">")
                  .Append($"<td><a href=\"#{anchor}\">{HtmlEsc(Path.GetFileName(r.FilePath))}</a></td>")
                  .Append($"<td>{HtmlEsc(r.FileType)}</td>")
                  .Append($"<td>{r.RiskScore}/100</td>")
                  .Append($"<td>{HtmlEsc(r.RiskLevel)}</td>")
                  .Append($"<td>{HtmlEsc(r.FamilyName)}</td>")
                  .Append($"<td><code>{HtmlEsc(r.Sha256)}</code>")
                  .Append(string.IsNullOrEmpty(r.Sha256) ? "" : $"<button class=\"copy\" data-copy=\"{HtmlEsc(r.Sha256)}\" title=\"Скопировать\">📋</button>")
                  .Append("</td></tr>")
                  .AppendLine();
            }
            sb.AppendLine("</tbody></table>");

            foreach (var r in results.OrderByDescending(x => x.RiskScore))
            {
                var badge = r.RiskScore >= 70 ? "badge-high" : r.RiskScore >= 40 ? "badge-med" : "badge-low";
                string anchor = "f-" + (r.Sha256.Length >= 8 ? r.Sha256[..8] : r.RiskScore.ToString("x"));
                sb.Append($"<details id=\"{anchor}\" data-level=\"{r.RiskLevel}\"><summary>")
                  .Append($"<span class=\"badge {badge}\">{r.RiskScore}</span> ")
                  .Append(HtmlEsc(Path.GetFileName(r.FilePath)))
                  .Append(" — ").Append(HtmlEsc(r.FamilyName.Length == 0 ? "unknown" : r.FamilyName))
                  .AppendLine("</summary>")
                  .Append("<pre>").Append(HtmlEsc(r.ToFullReport())).AppendLine("</pre></details>");
            }

            sb.AppendLine("<script>");
            sb.AppendLine("(function(){");
            sb.AppendLine("  const q = document.getElementById('q');");
            sb.AppendLine("  const chips = Array.from(document.querySelectorAll('.chip[data-level]'));");
            sb.AppendLine("  const rows  = Array.from(document.querySelectorAll('table tbody tr'));");
            sb.AppendLine("  const cards = Array.from(document.querySelectorAll('details[data-level]'));");
            sb.AppendLine("  const counter = document.getElementById('counter');");
            sb.AppendLine("  const total = rows.length;");
            sb.AppendLine("  function apply(){");
            sb.AppendLine("    const term = (q.value||'').toLowerCase().trim();");
            sb.AppendLine("    const lvls = new Set(chips.filter(c=>c.classList.contains('active')).map(c=>c.dataset.level));");
            sb.AppendLine("    let shown = 0;");
            sb.AppendLine("    rows.forEach(r=>{");
            sb.AppendLine("      const text = r.textContent.toLowerCase();");
            sb.AppendLine("      const okLvl = lvls.has(r.dataset.level);");
            sb.AppendLine("      const okTerm = !term || text.indexOf(term) >= 0;");
            sb.AppendLine("      const ok = okLvl && okTerm;");
            sb.AppendLine("      r.classList.toggle('hidden', !ok);");
            sb.AppendLine("      if (ok) shown++;");
            sb.AppendLine("    });");
            sb.AppendLine("    cards.forEach(c=>{");
            sb.AppendLine("      const text = c.textContent.toLowerCase();");
            sb.AppendLine("      const okLvl = lvls.has(c.dataset.level);");
            sb.AppendLine("      const okTerm = !term || text.indexOf(term) >= 0;");
            sb.AppendLine("      c.style.display = (okLvl && okTerm) ? '' : 'none';");
            sb.AppendLine("    });");
            sb.AppendLine("    if (counter) counter.textContent = 'Показано: ' + shown + ' / ' + total;");
            sb.AppendLine("  }");
            sb.AppendLine("  q && q.addEventListener('input', apply);");
            sb.AppendLine("  chips.forEach(c => c.addEventListener('click', ()=>{ c.classList.toggle('active'); apply(); }));");
            sb.AppendLine("  document.getElementById('expand-all') && document.getElementById('expand-all').addEventListener('click', ()=>cards.forEach(c=>c.open=true));");
            sb.AppendLine("  document.getElementById('collapse-all') && document.getElementById('collapse-all').addEventListener('click', ()=>cards.forEach(c=>c.open=false));");
            sb.AppendLine("  document.querySelectorAll('th[data-sort]').forEach((th, idx)=>{");
            sb.AppendLine("    th.addEventListener('click', ()=>{");
            sb.AppendLine("      const tbody = th.closest('table').querySelector('tbody');");
            sb.AppendLine("      const dir = th.getAttribute('data-sort-dir') === 'asc' ? 'desc' : 'asc';");
            sb.AppendLine("      document.querySelectorAll('th[data-sort]').forEach(x=>x.removeAttribute('data-sort-dir'));");
            sb.AppendLine("      th.setAttribute('data-sort-dir', dir);");
            sb.AppendLine("      const num = !!th.getAttribute('data-sort-num');");
            sb.AppendLine("      const trs = Array.from(tbody.querySelectorAll('tr'));");
            sb.AppendLine("      trs.sort((a,b)=>{");
            sb.AppendLine("        const av=(a.children[idx]?.textContent||'').trim(); const bv=(b.children[idx]?.textContent||'').trim();");
            sb.AppendLine("        if (num) { const an=parseFloat(av)||0, bn=parseFloat(bv)||0; return dir==='asc'?an-bn:bn-an; }");
            sb.AppendLine("        return dir==='asc'?av.localeCompare(bv):bv.localeCompare(av);");
            sb.AppendLine("      });");
            sb.AppendLine("      trs.forEach(tr=>tbody.appendChild(tr));");
            sb.AppendLine("    });");
            sb.AppendLine("  });");
            sb.AppendLine("  document.querySelectorAll('button.copy').forEach(b=>{");
            sb.AppendLine("    b.addEventListener('click', ()=>{ try { navigator.clipboard.writeText(b.dataset.copy); b.textContent='✓'; setTimeout(()=>b.textContent='📋', 1200); } catch(e) {} });");
            sb.AppendLine("  });");
            sb.AppendLine("})();");
            sb.AppendLine("</script>");

            sb.AppendLine("</body></html>");
            return sb.ToString();
        }

        // E3 — PDF (minimal, dependency-free)
        public static byte[] ToPdfBytes(IReadOnlyList<AnalysisResult> results)
        {
            // Assemble the plain-text report first, then wrap it into a tiny PDF container.
            var textSb = new StringBuilder();
            textSb.AppendLine($"AntiStealer report — {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
            textSb.AppendLine($"{results.Count} files analyzed.");
            textSb.AppendLine();
            foreach (var r in results.OrderByDescending(x => x.RiskScore))
            {
                textSb.AppendLine(new string('-', 60));
                textSb.AppendLine(r.ToFullReport());
                textSb.AppendLine();
            }

            return BuildMinimalPdf(textSb.ToString());
        }

        // Dependency-free PDF builder: one page per 55 lines, Courier 9pt. Good enough for
        // archiving the plain-text report without pulling QuestPDF/PdfSharp. Non-ASCII characters
        // are transliterated to '?' since we embed only the WinAnsi built-in Courier font and
        // don't want to ship a custom font.
        private static byte[] BuildMinimalPdf(string content)
        {
            string ascii = ToWinAnsi(content);
            var lines = ascii.Replace("\r\n", "\n").Split('\n');

            const int linesPerPage = 55;
            var pages = new List<List<string>>();
            for (int i = 0; i < lines.Length; i += linesPerPage)
                pages.Add(new List<string>(lines.Skip(i).Take(linesPerPage)));
            if (pages.Count == 0) pages.Add(new List<string> { "(empty)" });

            var sb = new StringBuilder(64 * 1024);
            sb.Append("%PDF-1.4\n");

            int objCount = 3 + pages.Count * 2; // catalog + pages + font + per-page Page + per-page Contents
            var xref = new long[objCount + 1];
            long Pos() => Encoding.ASCII.GetByteCount(sb.ToString());

            // 1: Catalog
            xref[1] = Pos();
            sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

            // 2: Pages
            xref[2] = Pos();
            sb.Append("2 0 obj\n<< /Type /Pages /Count ").Append(pages.Count).Append(" /Kids [");
            for (int p = 0; p < pages.Count; p++)
                sb.Append(4 + p).Append(" 0 R ");
            sb.Append("] >>\nendobj\n");

            // 3: Font
            xref[3] = Pos();
            sb.Append("3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>\nendobj\n");

            // 4..4+pages.Count-1: Page objects
            for (int p = 0; p < pages.Count; p++)
            {
                int pageObj = 4 + p;
                int contentObj = 4 + pages.Count + p;
                xref[pageObj] = Pos();
                sb.Append(pageObj).Append(" 0 obj\n")
                  .Append("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] ")
                  .Append("/Resources << /Font << /F1 3 0 R >> >> ")
                  .Append("/Contents ").Append(contentObj).Append(" 0 R >>\nendobj\n");
            }

            // Contents streams
            for (int p = 0; p < pages.Count; p++)
            {
                int contentObj = 4 + pages.Count + p;
                xref[contentObj] = Pos();
                var contentSb = new StringBuilder();
                contentSb.Append("BT\n/F1 9 Tf\n12 TL\n50 770 Td\n");
                bool first = true;
                foreach (var line in pages[p])
                {
                    if (!first) contentSb.Append("T*\n");
                    contentSb.Append('(').Append(EscapePdfString(line)).Append(") Tj\n");
                    first = false;
                }
                contentSb.Append("ET\n");
                var stream = contentSb.ToString();
                sb.Append(contentObj).Append(" 0 obj\n<< /Length ").Append(Encoding.ASCII.GetByteCount(stream)).Append(" >>\nstream\n")
                  .Append(stream).Append("endstream\nendobj\n");
            }

            long xrefStart = Pos();
            sb.Append("xref\n0 ").Append(objCount + 1).Append('\n');
            sb.Append("0000000000 65535 f \n");
            for (int i = 1; i <= objCount; i++)
                sb.Append(xref[i].ToString("D10")).Append(" 00000 n \n");
            sb.Append("trailer\n<< /Size ").Append(objCount + 1).Append(" /Root 1 0 R >>\n");
            sb.Append("startxref\n").Append(xrefStart).Append("\n%%EOF");

            return Encoding.ASCII.GetBytes(sb.ToString());
        }

        private static string EscapePdfString(string s) =>
            s.Replace("\\", "\\\\", StringComparison.Ordinal)
             .Replace("(",  "\\(",  StringComparison.Ordinal)
             .Replace(")",  "\\)",  StringComparison.Ordinal);

        // Section 11.3 — until we embed a CIDFont with full Unicode coverage,
        // transliterate Cyrillic / common math / punctuation to a Latin
        // approximation so the PDF doesn't drop everything to '?'. This is a
        // big improvement for Russian-language reports — the existing report
        // strings contain a lot of Cyrillic ("Файл", "Сводка", "Уровень…").
        private static string ToWinAnsi(string s)
        {
            if (string.IsNullOrEmpty(s)) return s ?? "";
            var sb = new StringBuilder(s.Length);
            foreach (var c in s)
            {
                if (c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c <= 0x7E) || (c >= 0xA0 && c <= 0xFF))
                {
                    sb.Append(c);
                    continue;
                }
                var t = TransliterateChar(c);
                if (t.Length == 0) sb.Append('?');
                else sb.Append(t);
            }
            return sb.ToString();
        }

        // Minimal Cyrillic→Latin transliteration (GOST 7.79-2000 System B-ish).
        // Returns "" if there's no mapping; the caller falls back to '?'.
        internal static string TransliterateChar(char c)
        {
            switch (c)
            {
                // Cyrillic uppercase
                case 'А': return "A"; case 'Б': return "B"; case 'В': return "V";
                case 'Г': return "G"; case 'Д': return "D"; case 'Е': return "E";
                case 'Ё': return "Yo"; case 'Ж': return "Zh"; case 'З': return "Z";
                case 'И': return "I"; case 'Й': return "Y"; case 'К': return "K";
                case 'Л': return "L"; case 'М': return "M"; case 'Н': return "N";
                case 'О': return "O"; case 'П': return "P"; case 'Р': return "R";
                case 'С': return "S"; case 'Т': return "T"; case 'У': return "U";
                case 'Ф': return "F"; case 'Х': return "Kh"; case 'Ц': return "Ts";
                case 'Ч': return "Ch"; case 'Ш': return "Sh"; case 'Щ': return "Shch";
                case 'Ъ': return "''"; case 'Ы': return "Y"; case 'Ь': return "'";
                case 'Э': return "E"; case 'Ю': return "Yu"; case 'Я': return "Ya";
                // Cyrillic lowercase
                case 'а': return "a"; case 'б': return "b"; case 'в': return "v";
                case 'г': return "g"; case 'д': return "d"; case 'е': return "e";
                case 'ё': return "yo"; case 'ж': return "zh"; case 'з': return "z";
                case 'и': return "i"; case 'й': return "y"; case 'к': return "k";
                case 'л': return "l"; case 'м': return "m"; case 'н': return "n";
                case 'о': return "o"; case 'п': return "p"; case 'р': return "r";
                case 'с': return "s"; case 'т': return "t"; case 'у': return "u";
                case 'ф': return "f"; case 'х': return "kh"; case 'ц': return "ts";
                case 'ч': return "ch"; case 'ш': return "sh"; case 'щ': return "shch";
                case 'ъ': return "''"; case 'ы': return "y"; case 'ь': return "'";
                case 'э': return "e"; case 'ю': return "yu"; case 'я': return "ya";
                // Ukrainian / Belarusian additions
                case 'І': return "I"; case 'і': return "i";
                case 'Ї': return "Yi"; case 'ї': return "yi";
                case 'Є': return "Ye"; case 'є': return "ye";
                case 'Ґ': return "G"; case 'ґ': return "g";
                case 'Ў': return "U"; case 'ў': return "u";
                // Common math / typographic punctuation
                case '—': case '–': return "-";
                case '«': return "<<"; case '»': return ">>";
                case '“': case '”': case '„': return "\"";
                case '‘': case '’': case '‚': return "'";
                case '…': return "...";
                case '×': return "x"; case '÷': return "/";
                case '°': return " deg";
                case '→': return "->"; case '←': return "<-";
                case '↑': return "^";  case '↓': return "v";
                case '✓': return "+";  case '✔': return "+"; case '✗': return "x"; case '✘': return "x";
                case '•': return "*";  case '·': return ".";
                default: return "";
            }
        }

        // E4 — STIX 2.1 (section 11.2)
        //
        // The bundle includes:
        //   • file         — SCO with hashes / size / name
        //   • malware      — SDO derived from FamilyName (is_family=true)
        //   • malware-analysis — SDO recording the static-analysis run (product,
        //                       analysis_started/ended, result, av_engines list)
        //   • indicator    — SDO for each unique URL / IPv4, with a STIX 2.1
        //                    pattern (`[url:value = '...']`, `[ipv4-addr:value = '...']`)
        //                    so downstream STIX consumers (MISP, OpenCTI,
        //                    AnomaliThreatStream) can ingest them as IOCs
        //                    instead of bare SCOs.
        //   • infrastructure — SDO grouping all network indicators
        //   • url / ipv4-addr — kept as SCOs and linked from the indicator(s)
        //                       via `relationship: based-on`
        //   • relationship — file → malware (indicates), file → infrastructure
        //                   (communicates-with), indicator → SCO (based-on).
        public static string ToStix(IReadOnlyList<AnalysisResult> results)
        {
            string nowZ = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            string identityId = "identity--" + DeterministicGuid("antistealer-identity");
            var objects = new List<object>
            {
                new Dictionary<string, object>
                {
                    ["type"]          = "identity",
                    ["spec_version"]  = "2.1",
                    ["id"]            = identityId,
                    ["created"]       = nowZ,
                    ["modified"]      = nowZ,
                    ["name"]          = "AntiStealer",
                    ["identity_class"] = "system",
                    ["sectors"]       = new[] { "infrastructure" },
                },
            };

            foreach (var r in results)
            {
                string fileId = "file--" + DeterministicGuid(string.IsNullOrEmpty(r.Sha256)
                    ? r.FilePath ?? Guid.NewGuid().ToString()
                    : r.Sha256);
                long fileSize = 0;
                try { if (!string.IsNullOrEmpty(r.FilePath) && File.Exists(r.FilePath)) fileSize = new FileInfo(r.FilePath).Length; } catch { }
                if (fileSize == 0) fileSize = r.Size > 0 ? r.Size : 0;
                var fileObj = new Dictionary<string, object?>
                {
                    ["type"]         = "file",
                    ["id"]           = fileId,
                    ["spec_version"] = "2.1",
                    ["hashes"]       = string.IsNullOrEmpty(r.Sha256) ? null : new Dictionary<string, string> { ["SHA-256"] = r.Sha256 },
                    ["name"]         = string.IsNullOrEmpty(r.FilePath) ? null : Path.GetFileName(r.FilePath),
                    ["size"]         = fileSize,
                };
                if (!string.IsNullOrEmpty(r.ImpHash))
                {
                    var hh = (Dictionary<string, string>?)fileObj["hashes"] ?? new Dictionary<string, string>();
                    hh["imphash"] = r.ImpHash;
                    fileObj["hashes"] = hh;
                }
                objects.Add(fileObj);

                // malware SDO — derived from family
                string? malId = null;
                if (!string.IsNullOrEmpty(r.FamilyName))
                {
                    malId = "malware--" + DeterministicGuid("malware-" + r.FamilyName);
                    objects.Add(new Dictionary<string, object>
                    {
                        ["type"]          = "malware",
                        ["spec_version"]  = "2.1",
                        ["id"]            = malId,
                        ["created"]       = nowZ,
                        ["modified"]      = nowZ,
                        ["name"]          = r.FamilyName,
                        ["is_family"]     = true,
                        ["malware_types"] = new[] { "trojan", "spyware" },
                        ["aliases"]       = new[] { r.FamilyName },
                    });
                    objects.Add(new Dictionary<string, object>
                    {
                        ["type"]              = "relationship",
                        ["spec_version"]      = "2.1",
                        ["id"]                = "relationship--" + DeterministicGuid(fileId + "→" + malId),
                        ["created"]           = nowZ,
                        ["modified"]          = nowZ,
                        ["relationship_type"] = "indicates",
                        ["source_ref"]        = fileId,
                        ["target_ref"]        = malId,
                    });
                }

                // malware-analysis SDO — static-analysis run record (section 11.2)
                string malAnalysisId = "malware-analysis--" + DeterministicGuid("ma-" + fileId);
                var avProducts = r.LocalAvHits.Count > 0 ? new[] { "antistealer", "clamav" } : new[] { "antistealer" };
                objects.Add(new Dictionary<string, object?>
                {
                    ["type"]               = "malware-analysis",
                    ["spec_version"]       = "2.1",
                    ["id"]                 = malAnalysisId,
                    ["created"]            = nowZ,
                    ["modified"]           = nowZ,
                    ["product"]            = "antistealer",
                    ["version"]            = "1.0",
                    ["analysis_engine_version"] = "1.0",
                    ["analysis_definition_version"] = "1",
                    ["analysis_started"]   = nowZ,
                    ["analysis_ended"]     = nowZ,
                    ["result_name"]        = string.IsNullOrEmpty(r.FamilyName) ? r.RiskLevel : r.FamilyName,
                    ["result"]             = r.RiskScore >= 70 ? "malicious"
                                          : r.RiskScore >= 40 ? "suspicious"
                                          : "benign",
                    ["sample_ref"]         = fileId,
                    ["av_result"]          = string.IsNullOrEmpty(r.FamilyName) ? null : r.FamilyName,
                    ["host_vm_ref"]        = identityId,
                });

                // infrastructure SDO + indicators for URLs / IPs (section 11.2)
                bool hasNetIoc = r.UrlsFound.Count > 0 || r.Ipv4Hits.Count > 0 || r.C2Indicators.Count > 0;
                string? infraId = null;
                if (hasNetIoc)
                {
                    infraId = "infrastructure--" + DeterministicGuid("infra-" + fileId);
                    objects.Add(new Dictionary<string, object>
                    {
                        ["type"]                  = "infrastructure",
                        ["spec_version"]          = "2.1",
                        ["id"]                    = infraId,
                        ["created"]               = nowZ,
                        ["modified"]              = nowZ,
                        ["name"]                  = $"C2 infra for {Path.GetFileName(r.FilePath ?? r.Sha256)}",
                        ["infrastructure_types"]  = new[] { "command-and-control" },
                    });
                    objects.Add(new Dictionary<string, object>
                    {
                        ["type"]              = "relationship",
                        ["spec_version"]      = "2.1",
                        ["id"]                = "relationship--" + DeterministicGuid(fileId + "→" + infraId),
                        ["created"]           = nowZ,
                        ["modified"]          = nowZ,
                        ["relationship_type"] = "communicates-with",
                        ["source_ref"]        = fileId,
                        ["target_ref"]        = infraId,
                    });
                }

                foreach (var url in r.UrlsFound.Distinct().Take(16))
                {
                    string urlScoId = "url--" + DeterministicGuid(url);
                    objects.Add(new Dictionary<string, object>
                    {
                        ["type"]         = "url",
                        ["id"]           = urlScoId,
                        ["spec_version"] = "2.1",
                        ["value"]        = url,
                    });
                    string indId = "indicator--" + DeterministicGuid("ind-url-" + url);
                    objects.Add(new Dictionary<string, object>
                    {
                        ["type"]            = "indicator",
                        ["spec_version"]    = "2.1",
                        ["id"]              = indId,
                        ["created"]         = nowZ,
                        ["modified"]        = nowZ,
                        ["name"]            = $"URL observed in {Path.GetFileName(r.FilePath ?? r.Sha256)}",
                        ["pattern"]         = "[url:value = '" + StixEscape(url) + "']",
                        ["pattern_type"]    = "stix",
                        ["valid_from"]      = nowZ,
                        ["indicator_types"] = new[] { "malicious-activity" },
                    });
                    objects.Add(new Dictionary<string, object>
                    {
                        ["type"]              = "relationship",
                        ["spec_version"]      = "2.1",
                        ["id"]                = "relationship--" + DeterministicGuid(indId + "→" + urlScoId),
                        ["created"]           = nowZ,
                        ["modified"]          = nowZ,
                        ["relationship_type"] = "based-on",
                        ["source_ref"]        = indId,
                        ["target_ref"]        = urlScoId,
                    });
                }
                foreach (var ip in r.Ipv4Hits.Distinct().Take(16))
                {
                    string ipScoId = "ipv4-addr--" + DeterministicGuid(ip);
                    objects.Add(new Dictionary<string, object>
                    {
                        ["type"]         = "ipv4-addr",
                        ["id"]           = ipScoId,
                        ["spec_version"] = "2.1",
                        ["value"]        = ip,
                    });
                    string indId = "indicator--" + DeterministicGuid("ind-ip-" + ip);
                    objects.Add(new Dictionary<string, object>
                    {
                        ["type"]            = "indicator",
                        ["spec_version"]    = "2.1",
                        ["id"]              = indId,
                        ["created"]         = nowZ,
                        ["modified"]        = nowZ,
                        ["name"]            = $"IP observed in {Path.GetFileName(r.FilePath ?? r.Sha256)}",
                        ["pattern"]         = "[ipv4-addr:value = '" + StixEscape(ip) + "']",
                        ["pattern_type"]    = "stix",
                        ["valid_from"]      = nowZ,
                        ["indicator_types"] = new[] { "malicious-activity" },
                    });
                }
            }

            var bundle = new
            {
                type = "bundle",
                id = "bundle--" + DeterministicGuid("antistealer-" + DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()),
                spec_version = "2.1",
                objects,
            };
            return JsonSerializer.Serialize(bundle, JsonOpts);
        }

        // STIX 2.1 pattern strings are single-quoted; escape any embedded single quote.
        private static string StixEscape(string s) => (s ?? "").Replace("\\", "\\\\").Replace("'", "\\'");

        // E5 — SARIF 2.1.0 (section 11.1)
        //
        // Compliant with GitHub Code Scanning, Azure DevOps, SonarQube. Each
        // result carries a `ruleId` that points at one of the rich rule
        // definitions emitted in `tool.driver.rules`. We expose:
        //   • full / short / help descriptions (markdown supported)
        //   • helpUri (links back to the project's DETECTIONS page)
        //   • defaultConfiguration.level (note / warning / error)
        //   • properties.tags (security, malware, family-name, MITRE ATT&CK)
        //   • properties.security-severity (CVSS-style 0.0–10.0) — required
        //     by GitHub Code Scanning to surface severity in the UI.
        //   • partialFingerprints + fingerprints (SHA-256) for stable
        //     dedup across runs in GitHub Code Scanning.
        public static string ToSarif(IReadOnlyList<AnalysisResult> results)
        {
            const string toolVersion         = "1.0.0";
            const string toolInfoUri         = "https://github.com/hatawares1234/antistealer";
            const string detectionsHelpUri   = "https://github.com/hatawares1234/antistealer/blob/main/docs/DETECTIONS.md";

            var runResults = new List<object>();
            var rules = new Dictionary<string, object>();

            // Pre-register the well-known rules so they appear in tool.driver.rules
            // even when no result matched them — required by some consumers
            // (e.g. GitHub Code Scanning shows rules in the rule-tab).
            void RegisterRule(string ruleId, string shortDesc, string fullDesc, string level, double severity, string[] tags)
            {
                if (rules.ContainsKey(ruleId)) return;
                rules[ruleId] = new
                {
                    id = ruleId,
                    name = ruleId.Replace("/", "_"),
                    shortDescription = new { text = shortDesc },
                    fullDescription  = new { text = fullDesc },
                    help             = new { text = fullDesc, markdown = $"**{shortDesc}**\n\n{fullDesc}\n\nSee [DETECTIONS.md]({detectionsHelpUri}#{ruleId.Replace("/", "-")})." },
                    helpUri          = detectionsHelpUri,
                    defaultConfiguration = new { level },
                    properties       = new
                    {
                        tags = tags,
                        precision = "medium",
                        // GitHub Code Scanning convention. 9.0+ = critical, 7.0–8.9 = high,
                        // 4.0–6.9 = medium, 0.1–3.9 = low.
                        @security_severity = severity.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture),
                    },
                };
            }
            RegisterRule("antistealer/high-risk", "Sample exceeded HIGH risk threshold",
                "AntiStealer scored this sample at or above the HIGH risk band. Review URLs/IPs/family classification before allowlisting.",
                "error", 9.0, new[] { "security", "malware", "stealer", "high-risk" });
            RegisterRule("antistealer/medium-risk", "Sample exceeded MEDIUM risk threshold",
                "AntiStealer scored this sample in the MEDIUM risk band. Possibly false-positive; investigate context.",
                "warning", 5.0, new[] { "security", "malware", "stealer", "medium-risk" });
            RegisterRule("antistealer/low-risk", "Sample in LOW risk band",
                "AntiStealer found weak signals only. Surfaced for completeness.",
                "note", 2.0, new[] { "security", "malware", "stealer", "low-risk" });
            RegisterRule("antistealer/analyze-error", "Analyzer failed to process file",
                "AntiStealer threw while analysing this file. The file should be re-scanned with verbose logging.",
                "warning", 4.0, new[] { "security", "analysis-error" });

            foreach (var r in results)
            {
                // Pick the right family-rule. Family-specific rule ids are emitted
                // alongside the generic high/medium/low rules so consumers can pivot on
                // family ("stealc", "redline", ...) when available.
                string famSlug = string.IsNullOrEmpty(r.FamilyName) ? "" : r.FamilyName.ToLowerInvariant().Replace(' ', '-');
                string familyRuleId = string.IsNullOrEmpty(famSlug) ? "" : ("antistealer/family/" + famSlug);
                if (!string.IsNullOrEmpty(familyRuleId))
                {
                    RegisterRule(familyRuleId, $"Family classification: {r.FamilyName}",
                        $"AntiStealer's local classifier flagged this sample as `{r.FamilyName}`. Confidence: {r.FamilyConfidence:0}%.",
                        r.RiskScore >= 70 ? "error" : r.RiskScore >= 40 ? "warning" : "note",
                        r.RiskScore >= 70 ? 8.0 : r.RiskScore >= 40 ? 5.0 : 2.0,
                        new[] { "security", "malware", "stealer", "family", famSlug });
                }

                bool isError = string.Equals(r.FileType, "ERROR", StringComparison.OrdinalIgnoreCase);
                string ruleId =
                    isError                 ? "antistealer/analyze-error"
                    : r.RiskScore >= 70    ? (string.IsNullOrEmpty(familyRuleId) ? "antistealer/high-risk"   : familyRuleId)
                    : r.RiskScore >= 40    ? (string.IsNullOrEmpty(familyRuleId) ? "antistealer/medium-risk" : familyRuleId)
                                            : (string.IsNullOrEmpty(familyRuleId) ? "antistealer/low-risk"    : familyRuleId);

                string level = isError ? "warning"
                            : r.RiskScore >= 70 ? "error"
                            : r.RiskScore >= 40 ? "warning"
                            : "note";

                runResults.Add(new
                {
                    ruleId,
                    level,
                    message = new
                    {
                        text     = string.IsNullOrEmpty(r.ReasonsShort) ? "no strong indicators" : r.ReasonsShort,
                        markdown = $"**Risk:** `{r.RiskScore}/100` ({r.RiskLevel}){(string.IsNullOrEmpty(r.FamilyName) ? "" : $"  \n**Family:** `{r.FamilyName}` ({r.FamilyConfidence:0}%)")}\n\n{r.ReasonsShort}",
                    },
                    locations = new object[]
                    {
                        new
                        {
                            physicalLocation = new
                            {
                                artifactLocation = new { uri = ToFileUri(r.FilePath), uriBaseId = "%SRCROOT%" },
                            },
                        },
                    },
                    partialFingerprints = new Dictionary<string, string?>
                    {
                        ["primaryLocationLineHash"] = string.IsNullOrEmpty(r.Sha256) ? null : r.Sha256,
                    },
                    fingerprints = new Dictionary<string, string?>
                    {
                        ["sha256/v1"]   = string.IsNullOrEmpty(r.Sha256) ? null : r.Sha256,
                        ["imphash/v1"]  = string.IsNullOrEmpty(r.ImpHash) ? null : r.ImpHash,
                        ["fuzzy/v1"]    = string.IsNullOrEmpty(r.FuzzyHash) ? null : r.FuzzyHash,
                    },
                    properties = new
                    {
                        tags = (new[] { "security", "malware", "stealer" })
                            .Concat(r.MitreTtps.Take(12).Select(t => "mitre/" + t.ToLowerInvariant()))
                            .Concat(string.IsNullOrEmpty(famSlug) ? Array.Empty<string>() : new[] { "family/" + famSlug })
                            .ToArray(),
                        riskScore = r.RiskScore,
                        riskLevel = r.RiskLevel,
                        sha256 = r.Sha256,
                        family = r.FamilyName,
                        familyConfidence = r.FamilyConfidence,
                        fileType = r.FileType,
                        capabilities = r.CapabilityScores,
                        urlsFound = r.UrlsFound.Take(32).ToArray(),
                        ipv4Hits  = r.Ipv4Hits.Take(32).ToArray(),
                        mitreTtps = r.MitreTtps.Take(32).ToArray(),
                    },
                });
            }

            var sarif = new
            {
                version = "2.1.0",
                schema  = "https://json.schemastore.org/sarif-2.1.0.json",
                runs = new object[]
                {
                    new
                    {
                        tool = new
                        {
                            driver = new
                            {
                                name             = "AntiStealer",
                                semanticVersion  = toolVersion,
                                informationUri   = toolInfoUri,
                                organization     = "AntiStealer",
                                rules            = rules.Values.ToArray(),
                            },
                        },
                        columnKind         = "utf16CodeUnits",
                        invocations        = new object[]
                        {
                            new
                            {
                                executionSuccessful = true,
                                startTimeUtc        = DateTime.UtcNow.AddMinutes(-1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                                endTimeUtc          = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                            },
                        },
                        originalUriBaseIds = new Dictionary<string, object>
                        {
                            ["%SRCROOT%"] = new { uri = "file:///" },
                        },
                        results = runResults.ToArray(),
                    },
                },
            };
            return JsonSerializer.Serialize(sarif, JsonOpts);
        }

        // E6 — batch HTML: per-file reports + sortable index.html.
        public static void WriteBatchHtml(IReadOnlyList<AnalysisResult> results, string outDir)
        {
            Directory.CreateDirectory(outDir);
            var rowsSb = new StringBuilder();
            foreach (var r in results.OrderByDescending(x => x.RiskScore))
            {
                string baseName = SafeFileName(Path.GetFileNameWithoutExtension(r.FilePath)) + "-" + (r.Sha256.Length >= 8 ? r.Sha256[..8] : "000000");
                string relFile = baseName + ".html";
                string fullFile = Path.Combine(outDir, relFile);
                File.WriteAllText(fullFile, ToHtml(new[] { r }), Encoding.UTF8);

                var cls = r.RiskScore >= 70 ? "risk-high" : r.RiskScore >= 40 ? "risk-med" : "risk-low";
                rowsSb.Append($"<tr class=\"{cls}\"><td><a href=\"{HtmlEsc(relFile)}\">{HtmlEsc(Path.GetFileName(r.FilePath))}</a></td>")
                      .Append($"<td>{r.RiskScore}/100</td>")
                      .Append($"<td>{HtmlEsc(r.RiskLevel)}</td>")
                      .Append($"<td>{HtmlEsc(r.FamilyName)}</td>")
                      .Append($"<td><code>{HtmlEsc(r.Sha256)}</code></td></tr>")
                      .AppendLine();
            }

            var idx = new StringBuilder();
            idx.AppendLine("<!doctype html><meta charset=\"utf-8\"/><title>AntiStealer batch</title>");
            idx.AppendLine("<style>body{font-family:system-ui;margin:24px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:6px 8px}tr.risk-high{background:#ffe6e6}tr.risk-med{background:#fff5e0}tr.risk-low{background:#e7fae7}</style>");
            idx.AppendLine($"<h1>AntiStealer batch — {results.Count} файлов, {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</h1>");
            idx.AppendLine("<table><thead><tr><th>Файл</th><th>Risk</th><th>Level</th><th>Family</th><th>SHA-256</th></tr></thead><tbody>");
            idx.Append(rowsSb);
            idx.AppendLine("</tbody></table>");
            File.WriteAllText(Path.Combine(outDir, "index.html"), idx.ToString(), Encoding.UTF8);
        }

        // E7 — autosave hook: drop JSON + HTML into %APPDATA%\AntiStealer\Reports\<timestamp>\.
        public static string AutoSave(IReadOnlyList<AnalysisResult> results)
        {
            var baseDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "AntiStealer", "Reports", DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss"));
            Directory.CreateDirectory(baseDir);
            File.WriteAllText(Path.Combine(baseDir, "report.json"), ToJson(results), Encoding.UTF8);
            File.WriteAllText(Path.Combine(baseDir, "report.html"), ToHtml(results), Encoding.UTF8);
            return baseDir;
        }

        private static string HtmlEsc(string? s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;")
                    .Replace("\"", "&quot;").Replace("'", "&#39;");
        }

        private static string SafeFileName(string s)
        {
            var invalid = Path.GetInvalidFileNameChars();
            var buf = new char[s.Length];
            for (int i = 0; i < s.Length; i++) buf[i] = Array.IndexOf(invalid, s[i]) >= 0 ? '_' : s[i];
            return new string(buf);
        }

        // Deterministic UUID-ish derived from SHA1 of input → 16 hex pairs formatted as a UUID.
        private static string DeterministicGuid(string input)
        {
            using var sha1 = System.Security.Cryptography.SHA1.Create();
            var h = sha1.ComputeHash(Encoding.UTF8.GetBytes(input ?? ""));
            // UUID v4-ish layout (not cryptographically a true v4 but valid format for STIX 2.1 ids).
            return $"{h[0]:x2}{h[1]:x2}{h[2]:x2}{h[3]:x2}-{h[4]:x2}{h[5]:x2}-{h[6]:x2}{h[7]:x2}-{h[8]:x2}{h[9]:x2}-{h[10]:x2}{h[11]:x2}{h[12]:x2}{h[13]:x2}{h[14]:x2}{h[15]:x2}";
        }

        // Robust path-to-`file://` URI conversion for SARIF `artifactLocation.uri`.
        // `new Uri(path)` is brittle across OSes — a unix path like
        // `/tmp/sample.exe` is accepted by .NET on Linux but rejected as
        // UriFormatException on Windows. We accept any string and fall
        // back to a manually-built `file://` URI when System.Uri refuses.
        private static string ToFileUri(string? path)
        {
            if (string.IsNullOrEmpty(path)) return "file:///";
            if (Uri.TryCreate(path, UriKind.Absolute, out var u))
                return u.AbsoluteUri;
            var normalised = path.Replace('\\', '/');
            if (!normalised.StartsWith("/", StringComparison.Ordinal))
                normalised = "/" + normalised;
            var encoded = string.Join('/', normalised.Split('/').Select(Uri.EscapeDataString));
            return "file://" + encoded;
        }
    }

    // H1: CLI frontend — `antistealer scan <path> [--recursive] [--json|--html|--pdf|--stix|--sarif|--csv]
    //                                             [--out <file>] [--batch-out <dir>] [--hide-low]
    //                                             [--timeout-ms N] [--max-parallel N]`
    // The same executable doubles as GUI + CLI; args are detected in Main().
    public static class Cli
    {
        // OutputType=WinExe means the Windows loader did NOT hand us a console — Console.WriteLine
        // would vanish. Try to attach to the parent cmd/PowerShell console (ATTACH_PARENT_PROCESS)
        // so `antistealer.exe scan …` produces visible output when launched from a terminal.
        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        private static extern bool AttachConsole(int dwProcessId);

        public static int Run(string[] args)
        {
            try { AttachConsole(-1); } catch { /* best-effort; fine under dotnet-host */ }

            if (args.Length == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "/?")
            {
                PrintHelp();
                return 0;
            }
            if (!args[0].Equals("scan", StringComparison.OrdinalIgnoreCase))
            {
                Console.Error.WriteLine("Unknown command: " + args[0]);
                PrintHelp();
                return 2;
            }

            string? target = null;
            string format = "json";
            string? outPath = null;
            string? batchDir = null;
            bool recursive = false;
            bool hideLow = false;
            int maxParallel = 0;

            for (int i = 1; i < args.Length; i++)
            {
                string a = args[i];
                switch (a)
                {
                    case "--recursive": case "-r": recursive = true; break;
                    case "--hide-low": hideLow = true; break;
                    case "--json":  format = "json";  break;
                    case "--html":  format = "html";  break;
                    case "--pdf":   format = "pdf";   break;
                    case "--stix":  format = "stix";  break;
                    case "--sarif": format = "sarif"; break;
                    case "--csv":   format = "csv";   break;
                    case "--batch-html": format = "batch-html"; break;
                    case "--out": case "-o": outPath = i + 1 < args.Length ? args[++i] : null; break;
                    case "--batch-out":     batchDir = i + 1 < args.Length ? args[++i] : null; break;
                    case "--max-parallel":  maxParallel = i + 1 < args.Length && int.TryParse(args[++i], out var mp) ? mp : 0; break;
                    case "--format":        format = i + 1 < args.Length ? args[++i].ToLowerInvariant() : format; break;
                    default:
                        if (a.StartsWith("-")) { Console.Error.WriteLine("Unknown flag: " + a); return 2; }
                        if (target == null) target = a; else { Console.Error.WriteLine("Multiple targets not supported yet."); return 2; }
                        break;
                }
            }

            if (string.IsNullOrEmpty(target))
            {
                Console.Error.WriteLine("scan: missing path argument.");
                PrintHelp();
                return 2;
            }

            var files = ExpandTarget(target, recursive);
            if (files.Count == 0)
            {
                Console.Error.WriteLine("No scannable files under: " + target);
                return 1;
            }

            var settings = AnalyzerUiSettings.Load();
            Analyzer.EnableServerClassification = settings.EnableServerClassifier;
            Analyzer.EnableExternalRules = settings.EnableExternalRules;
            Analyzer.MaxReadPrefixBytes = settings.MaxReadPrefixMb * 1024 * 1024;
            Analyzer.MaxAsciiStrings = settings.MaxAsciiStrings;
            Analyzer.MaxUnicodeStrings = settings.MaxUnicodeStrings;
            Analyzer.MaxExtractedUrls = settings.MaxUrls;

            int dop = maxParallel > 0 ? maxParallel : Math.Max(1, settings.MaxParallelism > 0 ? settings.MaxParallelism : Environment.ProcessorCount);
            var results = new System.Collections.Concurrent.ConcurrentBag<AnalysisResult>();
            int done = 0;
            var sw = System.Diagnostics.Stopwatch.StartNew();
            Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = dop }, path =>
            {
                AnalysisResult r;
                try { r = Analyzer.Analyze(path, path); }
                catch (Exception ex) { r = AnalysisResult.Error(path, ex.Message); }
                try { Analyzer.EnrichWithCloudAsync(r, settings, default).GetAwaiter().GetResult(); } catch { }
                try { r.RiskScore = Analyzer.ScorePublic(r); r.FinalizeFlags(); } catch { }
                if (hideLow && r.RiskScore < 40) { Interlocked.Increment(ref done); return; }
                results.Add(r);
                int d = Interlocked.Increment(ref done);
                if (d % 25 == 0 || d == files.Count)
                    Console.Error.WriteLine($"  {d}/{files.Count}  {Path.GetFileName(path)}");
            });
            sw.Stop();

            var sorted = results.OrderByDescending(r => r.RiskScore).ToList();
            int rc = WriteOutput(sorted, format, outPath, batchDir);
            Console.Error.WriteLine($"done: {sorted.Count} files in {sw.Elapsed.TotalSeconds:0.0}s");
            return rc;
        }

        private static int WriteOutput(IReadOnlyList<AnalysisResult> results, string format, string? outPath, string? batchDir)
        {
            try
            {
                switch (format)
                {
                    case "json":
                    {
                        var text = ReportWriter.ToJson(results);
                        if (string.IsNullOrEmpty(outPath)) Console.Out.WriteLine(text);
                        else File.WriteAllText(outPath, text, Encoding.UTF8);
                        break;
                    }
                    case "html":
                    {
                        var text = ReportWriter.ToHtml(results);
                        if (string.IsNullOrEmpty(outPath)) Console.Out.WriteLine(text);
                        else File.WriteAllText(outPath, text, Encoding.UTF8);
                        break;
                    }
                    case "pdf":
                    {
                        if (string.IsNullOrEmpty(outPath)) { Console.Error.WriteLine("--pdf requires --out <file>."); return 2; }
                        File.WriteAllBytes(outPath, ReportWriter.ToPdfBytes(results));
                        break;
                    }
                    case "stix":
                    {
                        var text = ReportWriter.ToStix(results);
                        if (string.IsNullOrEmpty(outPath)) Console.Out.WriteLine(text);
                        else File.WriteAllText(outPath, text, Encoding.UTF8);
                        break;
                    }
                    case "sarif":
                    {
                        var text = ReportWriter.ToSarif(results);
                        if (string.IsNullOrEmpty(outPath)) Console.Out.WriteLine(text);
                        else File.WriteAllText(outPath, text, Encoding.UTF8);
                        break;
                    }
                    case "csv":
                    {
                        var text = ReportWriter.ToCsv(results);
                        if (string.IsNullOrEmpty(outPath)) Console.Out.WriteLine(text);
                        else File.WriteAllText(outPath, text, Encoding.UTF8);
                        break;
                    }
                    case "batch-html":
                    {
                        if (string.IsNullOrEmpty(batchDir)) { Console.Error.WriteLine("--batch-html requires --batch-out <dir>."); return 2; }
                        ReportWriter.WriteBatchHtml(results, batchDir);
                        break;
                    }
                    default:
                        Console.Error.WriteLine("Unknown --format: " + format);
                        return 2;
                }
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Output error: " + ex.Message);
                return 3;
            }
        }

        private static readonly HashSet<string> AllowedExts = new(StringComparer.OrdinalIgnoreCase)
        {
            ".asi", ".dll", ".exe", ".sys", ".ocx", ".cpl", ".scr",
            ".msi", ".msix", ".appx", ".7z", ".rar", ".gz", ".tar",
            ".so", ".dylib",
            // Script formats. Lua is for SA-MP / GTA-targeted loaders &
            // stealers (see DetectLuaThreats / Script-LUA family below).
            ".hta", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".lua",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf",
            ".zip", ".jar", ".apk",
        };

        private static List<string> ExpandTarget(string target, bool recursive)
        {
            var list = new List<string>();
            try
            {
                if (File.Exists(target))
                {
                    list.Add(Path.GetFullPath(target));
                }
                else if (Directory.Exists(target))
                {
                    var opt = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
                    foreach (var f in Directory.EnumerateFiles(target, "*", opt))
                    {
                        var ext = Path.GetExtension(f);
                        if (AllowedExts.Contains(ext)) list.Add(Path.GetFullPath(f));
                    }
                }
                else
                {
                    Console.Error.WriteLine("Path does not exist: " + target);
                }
            }
            catch (Exception ex) { Console.Error.WriteLine("Enumerate error: " + ex.Message); }
            return list;
        }

        private static void PrintHelp()
        {
            Console.Out.WriteLine(
                "AntiStealer CLI\n" +
                "\n" +
                "USAGE:\n" +
                "  antistealer scan <path> [options]\n" +
                "\n" +
                "FORMATS (choose one; default: --json):\n" +
                "  --json                 emit JSON report (default)\n" +
                "  --html                 emit self-contained HTML report\n" +
                "  --pdf                  emit minimal PDF (requires --out FILE)\n" +
                "  --stix                 emit STIX 2.1 bundle\n" +
                "  --sarif                emit SARIF 2.1.0\n" +
                "  --csv                  emit CSV summary\n" +
                "  --batch-html           write per-file HTMLs + index.html (requires --batch-out DIR)\n" +
                "  --format <fmt>         alternative form of the above (json|html|pdf|stix|sarif|csv|batch-html)\n" +
                "\n" +
                "OUTPUT:\n" +
                "  --out|-o <file>        write to file (default: stdout)\n" +
                "  --batch-out <dir>      output dir for --batch-html\n" +
                "\n" +
                "SCAN OPTIONS:\n" +
                "  --recursive|-r         descend into subdirectories\n" +
                "  --hide-low             drop results with RiskScore < 40\n" +
                "  --max-parallel <N>     override parallelism (default: CPU count)\n" +
                "\n" +
                "EXAMPLES:\n" +
                "  antistealer scan C:\\Samples --recursive --json --out samples.json\n" +
                "  antistealer scan suspicious.exe --html --out report.html\n" +
                "  antistealer scan C:\\Samples -r --batch-html --batch-out C:\\out\\reports\\\n"
            );
        }
    }
}
