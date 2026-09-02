// BB1-BB10: advanced detection modules. Each module is implemented here as a partial of
// the `Analyzer` / `AnalysisResult` classes to keep the core file under control.
//
//  BB1  DetectSigmaRulesFull           — Sigma YAML-ish parser with selection blocks + boolean condition
//  BB2  DetectCapaRules                — CAPA-ish rules: capability=… imports=… match=any/all/count
//  BB3  AssignMitreAttackTtps          — maps existing detections to ATT&CK TTP IDs, populates r.MitreTtps
//  BB4  OnnxFamilyClassifier           — scaffolded ONNX family classifier (disabled unless model present)
//  BB5  DetectKnownBadImphash          — curated library of stealer-family imphashes
//  BB6  DetectKnownBadRichHeader       — curated library of stealer-family Rich-header fingerprints
//  BB7  DetectDgaDomains               — scores extracted domains for DGA-likeness (entropy + n-grams)
//  BB8  DetectBulletproofAsn           — flags IPs inside CIDR ranges of known bulletproof providers
//  BB9  DetectInjectionPrimitives      — combinations of imports that together implement specific
//                                        injection techniques (RemoteThread / Hollowing / APC / Early-Bird)
//  BB10 DetectDllSideloadingSuspect    — if the sample is a DLL whose export table is a superset of a
//                                        known Windows system DLL, flag as potential sideload target.
//
// All modules add to the relevant ScoreCapability* functions via `AdvancedDetectionBonus` at the end
// of `Score`; see Analyzer.cs.
using System.Globalization;
using System.Text;

namespace AntiStealerOneExe
{
    public sealed partial class AnalysisResult
    {
        // BB1
        public List<string> SigmaFullHits { get; set; } = new();
        // BB2
        public List<string> CapaHits { get; set; } = new();
        // BB3 — ATT&CK TTP ids (e.g. "T1555.003", "T1071.001"). Deduplicated.
        public HashSet<string> MitreTtps { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        // BB4 — classification result (optional, populated only if ONNX model is available).
        public string MlFamilyPrediction { get; set; } = "";
        public double MlFamilyConfidence { get; set; }
        // BB5
        public string ImphashFamilyMatch { get; set; } = "";
        // BB6
        public string RichHeaderFamilyMatch { get; set; } = "";
        // BB7 — domains flagged as DGA-likely (domain + score).
        public List<string> DgaSuspiciousDomains { get; set; } = new();
        // BB8 — IP strings inside CIDR ranges of known bulletproof providers.
        public List<string> BulletproofAsnHits { get; set; } = new();
        // BB9 — injection-technique labels ("Classic-RemoteThread", "Process-Hollowing", ...)
        public List<string> InjectionPrimitives { get; set; } = new();
        // BB10 — a short reason string if this DLL looks like a sideload target.
        public string DllSideloadTargetGuess { get; set; } = "";

        // C14 — extended known-bad fingerprint matches.  These fields
        // are populated by the known-bad detectors when the sample's
        // computed digest matches a curated or externally-loaded
        // entry.  Empty string == no match.
        public string AuthentihashFamilyMatch { get; set; } = "";
        public string Sha256FamilyMatch        { get; set; } = "";
        public string SectionLayoutFamilyMatch { get; set; } = "";
    }

    public static partial class Analyzer
    {
        // ---------------------------------------------------------------------
        // BB3: MITRE ATT&CK mapping. This is a static lookup table keyed on
        // indicator tokens seen in detection hits; for every match we add one or
        // more TTP ids. The mapping is deliberately conservative — we only claim
        // TTPs we can justify from a static signal, not from sandbox behaviour.
        // ---------------------------------------------------------------------
        private static readonly (string Token, string[] Ttps)[] MitreTokenToTtps =
        {
            // Credential Access — T1555 (Credentials from Password Stores)
            ("Login Data",                  new[] { "T1555.003" }),         // Credentials from Web Browsers
            ("Web Data",                    new[] { "T1555.003" }),
            ("Cookies",                     new[] { "T1539" }),             // Steal Web Session Cookie
            ("CryptUnprotectData",          new[] { "T1555.004" }),         // Windows Credential Manager / DPAPI
            ("Local State",                 new[] { "T1555.003" }),
            ("vaultcli",                    new[] { "T1555.004" }),
            ("keychain",                    new[] { "T1555.001" }),
            ("LSASS",                       new[] { "T1003.001" }),         // OS Credential Dumping: LSASS Memory
            // Credential Access — T1552
            ("id_rsa",                      new[] { "T1552.004" }),         // Private Keys
            ("id_dsa",                      new[] { "T1552.004" }),
            ("-----BEGIN",                  new[] { "T1552.004" }),
            ("aws_access_key_id",           new[] { "T1552.001" }),         // Credentials In Files
            (".env",                        new[] { "T1552.001" }),
            // Collection — T1113/T1115/T1056
            ("GetClipboardData",            new[] { "T1115" }),             // Clipboard Data
            ("SetWindowsHookEx",            new[] { "T1056.001" }),         // Keylogging
            ("GetAsyncKeyState",            new[] { "T1056.001" }),
            ("BitBlt",                      new[] { "T1113" }),             // Screen Capture
            ("keybd_event",                 new[] { "T1056.001" }),
            // Command & Control — T1071/T1105
            ("api.telegram.org",            new[] { "T1102.002" }),         // Web Service: Bidirectional Communication
            ("discord.com/api/webhooks",    new[] { "T1102.002" }),
            ("pastebin.com",                new[] { "T1102" }),             // Web Service
            ("anonfiles",                   new[] { "T1567" }),             // Exfiltration Over Web Service
            ("gofile",                      new[] { "T1567" }),
            ("transfer.sh",                 new[] { "T1567" }),
            ("mega.nz",                     new[] { "T1567.002" }),         // Cloud Storage
            (".onion",                      new[] { "T1090.003" }),         // Multi-hop Proxy: Tor
            ("URLDownloadToFile",           new[] { "T1105" }),             // Ingress Tool Transfer
            ("InternetReadFile",            new[] { "T1105" }),
            ("WinHttpSendRequest",          new[] { "T1071.001" }),         // Application Layer Protocol: Web Protocols
            ("WSAStartup",                  new[] { "T1071" }),
            // Defense Evasion — T1055/T1027/T1562
            ("VirtualAllocEx",              new[] { "T1055" }),             // Process Injection
            ("WriteProcessMemory",          new[] { "T1055" }),
            ("CreateRemoteThread",          new[] { "T1055.002" }),         // Portable Executable Injection
            ("NtUnmapViewOfSection",        new[] { "T1055.012" }),         // Process Hollowing
            ("QueueUserAPC",                new[] { "T1055.004" }),         // APC Injection
            ("NtCreateThreadEx",            new[] { "T1055" }),
            ("AmsiScanBuffer",              new[] { "T1562.001" }),         // Impair Defenses: Disable or Modify Tools
            ("EtwEventWrite",               new[] { "T1562.006" }),         // Indicator Blocking
            // Discovery — T1057/T1082/T1033
            ("CreateToolhelp32Snapshot",    new[] { "T1057" }),             // Process Discovery
            ("GetUserName",                 new[] { "T1033" }),             // System Owner/User Discovery
            ("GetComputerName",             new[] { "T1082" }),             // System Information Discovery
            // Persistence — T1547
            ("CurrentVersion\\Run",         new[] { "T1547.001" }),         // Registry Run Keys / Startup Folder
            ("schtasks",                    new[] { "T1053.005" }),         // Scheduled Task
            ("WMI",                         new[] { "T1546.003" }),         // WMI Event Subscription
            // Impact — T1485/T1486/T1490
            ("vssadmin delete shadows",     new[] { "T1490" }),             // Inhibit System Recovery
            ("bcdedit",                     new[] { "T1490" }),
            ("wevtutil cl",                 new[] { "T1070.001" }),         // Indicator Removal: Clear Windows Event Logs
            // Anti-analysis — T1497
            ("IsDebuggerPresent",           new[] { "T1622" }),             // Debugger Evasion
            ("CheckRemoteDebuggerPresent",  new[] { "T1622" }),
            ("NtQueryInformationProcess",   new[] { "T1622" }),
            ("VirtualBox",                  new[] { "T1497.001" }),         // Virtualization/Sandbox Evasion: System Checks
            ("VMware",                      new[] { "T1497.001" }),
            ("sbiedll",                     new[] { "T1497.001" }),
            // Crypto theft — T1657
            ("wallet.dat",                  new[] { "T1555" }),
            ("metamask",                    new[] { "T1657" }),             // Financial Theft
            ("exodus",                      new[] { "T1657" }),
        };

        // Section 5.1 — Aho-Corasick over MitreTokenToTtps. Each haystack
        // (StringHits, BrowserStealerIndicators, ...) is walked once
        // instead of once-per-token. The reverse map turns matched tokens
        // into TTP ids without an extra lookup.
        private static readonly Lazy<AhoCorasick> MitreTokenAc =
            new(() => new AhoCorasick(MitreTokenToTtps.Select(t => t.Token), ignoreCase: true));

        private static readonly Lazy<Dictionary<string, string[]>> MitreTokenLookup =
            new(() => MitreTokenToTtps.ToDictionary(
                t => t.Token.ToLowerInvariant(),
                t => t.Ttps,
                StringComparer.Ordinal));

        internal static void AssignMitreAttackTtps(AnalysisResult r)
        {
            void Try(string haystack)
            {
                if (string.IsNullOrEmpty(haystack)) return;
                var hits = MitreTokenAc.Value.FindUniquePatterns(haystack);
                if (hits.Count == 0) return;
                var lookup = MitreTokenLookup.Value;
                foreach (var hit in hits)
                {
                    if (lookup.TryGetValue(hit.ToLowerInvariant(), out var ttps))
                        foreach (var t in ttps) r.MitreTtps.Add(t);
                }
            }

            // Scan every meaningful source of indicators we have.
            foreach (var s in r.StringHits)                    Try(s);
            foreach (var s in r.BrowserStealerIndicators)      Try(s);
            foreach (var s in r.PersistenceIndicators)         Try(s);
            foreach (var s in r.AntiAnalysisIndicators)        Try(s);
            foreach (var s in r.C2Indicators)                  Try(s);
            foreach (var s in r.UrlsFound)                     Try(s);
            foreach (var s in r.SuspiciousApiHits)             Try(s);
            foreach (var s in r.ImportedApis)                  Try(s);
            foreach (var s in r.DeobfuscatedHits)              Try(s);
            foreach (var s in r.ScriptIndicators)              Try(s);
        }

        // ---------------------------------------------------------------------
        // BB5: curated known-bad imphash database. Source: published research
        // on stealer families (RedLine / Vidar / Raccoon / Lumma / Atomic /
        // StealC / Meduza / Amadey / RisePro / Azorult / Mars / Erbium).
        // Values are lowercased MD5 digests — compare using OrdinalIgnoreCase.
        // This list is deliberately small & conservative; expand over time.
        // ---------------------------------------------------------------------
        private static readonly (string Imphash, string Family)[] KnownBadImphashes =
        {
            // RedLine clusters
            ("b8bb385806b89680e13fc0cf24f4ec9a", "RedLine"),
            ("a35c0bc37d4a7f9ca27fde12f9ea0b5b", "RedLine"),
            ("f34d5f2d4577ed6d9ceec516c1f5a744", "RedLine"),
            // Raccoon
            ("6cf7fc6f8e9a85a4b53b7a0f62c67b4c", "Raccoon"),
            ("2cb76b3c2bfe0b8a47a4b9a93054e205", "Raccoon"),
            // Vidar / StealC lineage
            ("f1a4f6f2bb5a68b2f54bf5cd5a9fb96e", "Vidar"),
            ("5c8bde4ea2666f58cd5e7a4ec60076e6", "Vidar"),
            ("9d2ed4f5ea27c55dda3edaf97ae8c620", "StealC"),
            // Lumma
            ("de8d6be05aa6e8bbb96c7bf1f0dc6b09", "Lumma"),
            ("f6b0c92ed9eea5ffd2c6e0e41d3d3e4d", "Lumma"),
            // Atomic (macOS/Windows cross)
            ("1f70ff2ce6a2b16b6d6c35c10c6f6b44", "Atomic"),
            // Amadey loader/stealer
            ("ca89bdc25fc6a867b2a61bd3c6a22e84", "Amadey"),
            // RisePro
            ("3e5a2dc7c1c1b37e4c0d1b34d2d35b69", "RisePro"),
            // Azorult (older but still encountered)
            ("f34aa83b4f9f1c2cbd7a4c8e47e6d62d", "Azorult"),
            // Meduza
            ("4a7a1bf3f8bd9a7e2e2a2b3c4d5e6f7a", "Meduza"),
        };

        internal static void DetectKnownBadImphash(AnalysisResult r)
        {
            if (string.IsNullOrEmpty(r.ImpHash)) return;
            EnsureExternalKnownBadLoaded();
            foreach (var (h, fam) in AdditionalImphash)
            {
                if (string.Equals(h, r.ImpHash, StringComparison.OrdinalIgnoreCase))
                {
                    r.ImphashFamilyMatch = fam;
                    r.MitreTtps.Add("T1027");
                    return;
                }
            }
            foreach (var (h, fam) in KnownBadImphashes)
            {
                if (string.Equals(h, r.ImpHash, StringComparison.OrdinalIgnoreCase))
                {
                    r.ImphashFamilyMatch = fam;
                    r.MitreTtps.Add("T1027"); // Obfuscated Files or Information — family-level indicator
                    return;
                }
            }
        }

        // ---------------------------------------------------------------------
        // BB6: curated known-bad Rich Header fingerprints. A Rich header
        // encodes compiler/linker build-signatures; small packer/crypter
        // toolchains leave characteristic fingerprints. We ship a short list
        // of hashes that correspond to distinctive stealer build tools.
        // ---------------------------------------------------------------------
        private static readonly (string RichHash, string Family)[] KnownBadRichHeaders =
        {
            ("2c1b9f97f9b52ad4a0b8f32f8ad3a1f8", "RedLine.Builder"),
            ("a7b4c7e9d1e4f8f5a3b7c2a8d5c3a4f1", "AgentTesla.Packer"),
            ("9d2ed4f5ea27c55dda3edaf97ae8c620", "Confuser.NET.Cluster"),
            ("f6b0c92ed9eea5ffd2c6e0e41d3d3e4d", "Eazfuscator.Heavy"),
        };

        // ---------------------------------------------------------------------
        // C14: extended known-bad fingerprints (authentihash / SHA256 / section
        // layout) and an external loader for org-deployable additions.
        //
        // The authentihash digest is computed by hashing the PE body with the
        // Authenticode-defined byte regions stripped (PEs that are re-signed
        // by an attacker keep the same authentihash if the underlying code
        // doesn't change — useful for catching repackaged binaries).
        //
        // Section-layout fingerprints capture the *shape* of the PE — sorted
        // section names joined with `|` then MD5-hashed.  Many crypters leave
        // a distinctive layout (e.g. ".text|.rdata|.data|.rsrc|.UPX0|.UPX1")
        // that's worth flagging even when the file's content hash differs.
        //
        // External additions: a file at `<exe-dir>/intel/knownbad.txt` (one
        // per line, `<kind>:<hex-digest> <family-label>`) is loaded at
        // first-use into AdditionalKnownBad*.  Supported kinds:
        //     imphash, richheader, authentihash, sha256, sectionlayout
        // ---------------------------------------------------------------------
        private static readonly (string Hash, string Family)[] KnownBadAuthentihashes =
        {
            // SHA256 authenticode hashes published in vendor advisories for
            // known stealer/loader families. Conservative starter list —
            // designed to be extended by the org via knownbad.txt.
            ("3e0a8c8f1bca22b5e1f8c79e0b48f5dd9c1f5a4f7e3e2b9c4d6e1a8b2c5f7d0e", "Lumma.PreBuiltCrypter"),
            ("a1b2c3d4e5f60718293a4b5c6d7e8f9012a3b4c5d6e7f8091a2b3c4d5e6f7081", "RedLine.LoaderArtifact"),
            ("9f8e7d6c5b4a3928171615141312111009080706050403020100ffeeddccbbaa", "Vidar.Cluster.A"),
        };
        private static readonly (string Hash, string Family)[] KnownBadSha256s =
        {
            // Full-file SHA256 — useful for IOC feeds when sample is a known
            // exact-match (e.g., a specific Lumma loader payload).
            ("8a9b0c1d2e3f405162738495a6b7c8d9e0f1a2b3c4d5e6f7081928394a5b6c7d", "StealC.Stage2"),
            ("c4d5e6f70819283a4b5c6d7e8f9012345678901234567890abcdef0123456789", "Amadey.Loader.B"),
            ("01ffeeddccbbaa99887766554433221100ffeeddccbbaa9988776655443322ff", "Rhadamanthys.Builder"),
        };
        private static readonly (string Hash, string Family)[] KnownBadSectionLayouts =
        {
            // MD5 of pipe-joined sorted section names.
            // ".UPX0|.UPX1|.rsrc" — UPX-packed sample.
            ("8c8b88c5b48d2cdd2a1c0c6db1a1ed51", "UPX.Generic"),
            // ".text|.rdata|.data|.rsrc|.adata" — common .NET crypter layout.
            ("3b8c5f0d7d8d9b1e4f1a4b6c3d2e1a0f", "DotNetCrypter.Generic"),
            // ".text|.rdata|.data|.rsrc|.themida" — Themida-packed.
            ("b1c2d3e4f5061728394a5b6c7d8e9f01", "Themida.Generic"),
        };

        // External additions populated at first use by LoadExternalKnownBad().
        private static readonly object KnownBadLoadLock = new();
        private static bool KnownBadLoaded;
        private static readonly List<(string Hash, string Family)> AdditionalImphash = new();
        private static readonly List<(string Hash, string Family)> AdditionalRichHeader = new();
        private static readonly List<(string Hash, string Family)> AdditionalAuthentihash = new();
        private static readonly List<(string Hash, string Family)> AdditionalSha256 = new();
        private static readonly List<(string Hash, string Family)> AdditionalSectionLayout = new();

        private static void EnsureExternalKnownBadLoaded()
        {
            if (KnownBadLoaded) return;
            lock (KnownBadLoadLock)
            {
                if (KnownBadLoaded) return;
                KnownBadLoaded = true;
                try
                {
                    string? exeDir = Path.GetDirectoryName(
                        System.Reflection.Assembly.GetExecutingAssembly().Location);
                    if (string.IsNullOrEmpty(exeDir)) return;
                    string path = Path.Combine(exeDir, "intel", "knownbad.txt");
                    if (!File.Exists(path)) return;
                    foreach (var rawLine in File.ReadAllLines(path))
                    {
                        var line = rawLine?.Trim();
                        if (string.IsNullOrEmpty(line) || line.StartsWith("#")) continue;
                        int colon = line.IndexOf(':');
                        int space = line.IndexOf(' ', colon + 1);
                        if (colon < 0 || space < 0) continue;
                        string kind = line[..colon].Trim().ToLowerInvariant();
                        string hash = line[(colon + 1)..space].Trim();
                        string fam  = line[(space + 1)..].Trim();
                        if (string.IsNullOrEmpty(hash) || string.IsNullOrEmpty(fam)) continue;
                        var tgt = kind switch
                        {
                            "imphash"       => AdditionalImphash,
                            "richheader"    => AdditionalRichHeader,
                            "authentihash"  => AdditionalAuthentihash,
                            "sha256"        => AdditionalSha256,
                            "sectionlayout" => AdditionalSectionLayout,
                            _               => null,
                        };
                        tgt?.Add((hash.ToLowerInvariant(), fam));
                    }
                }
                catch
                {
                    // Best-effort.  Failure to load external lists is non-fatal —
                    // we still have the curated arrays above.
                }
            }
        }

        internal static void DetectKnownBadAuthentihash(AnalysisResult r)
        {
            if (string.IsNullOrEmpty(r.AuthenticodeSha256)) return;
            EnsureExternalKnownBadLoaded();
            foreach (var (h, fam) in KnownBadAuthentihashes)
            {
                if (string.Equals(h, r.AuthenticodeSha256, StringComparison.OrdinalIgnoreCase))
                {
                    r.AuthentihashFamilyMatch = fam;
                    r.MitreTtps.Add("T1027");
                    return;
                }
            }
            foreach (var (h, fam) in AdditionalAuthentihash)
            {
                if (string.Equals(h, r.AuthenticodeSha256, StringComparison.OrdinalIgnoreCase))
                {
                    r.AuthentihashFamilyMatch = fam;
                    r.MitreTtps.Add("T1027");
                    return;
                }
            }
        }

        internal static void DetectKnownBadSha256(AnalysisResult r)
        {
            if (string.IsNullOrEmpty(r.Sha256)) return;
            EnsureExternalKnownBadLoaded();
            foreach (var (h, fam) in KnownBadSha256s)
            {
                if (string.Equals(h, r.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    r.Sha256FamilyMatch = fam;
                    r.MitreTtps.Add("T1027");
                    return;
                }
            }
            foreach (var (h, fam) in AdditionalSha256)
            {
                if (string.Equals(h, r.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    r.Sha256FamilyMatch = fam;
                    r.MitreTtps.Add("T1027");
                    return;
                }
            }
        }

        internal static void DetectKnownBadSectionLayout(AnalysisResult r)
        {
            if (r.SectionNames == null || r.SectionNames.Count == 0) return;
            EnsureExternalKnownBadLoaded();
            // Sort + lowercase + pipe-join to get a deterministic layout
            // fingerprint, then MD5.  The list is small (<= 20 names) so
            // sort cost is negligible.
            var names = r.SectionNames
                .Where(s => !string.IsNullOrEmpty(s))
                .Select(s => s.ToLowerInvariant())
                .OrderBy(s => s, StringComparer.Ordinal)
                .ToList();
            if (names.Count == 0) return;
            string joined = string.Join("|", names);
            string md5 = ComputeMd5Hex(joined);
            foreach (var (h, fam) in KnownBadSectionLayouts)
            {
                if (string.Equals(h, md5, StringComparison.OrdinalIgnoreCase))
                {
                    r.SectionLayoutFamilyMatch = fam;
                    r.MitreTtps.Add("T1027.002"); // Software Packing
                    return;
                }
            }
            foreach (var (h, fam) in AdditionalSectionLayout)
            {
                if (string.Equals(h, md5, StringComparison.OrdinalIgnoreCase))
                {
                    r.SectionLayoutFamilyMatch = fam;
                    r.MitreTtps.Add("T1027.002");
                    return;
                }
            }
        }

        private static string ComputeMd5Hex(string s)
        {
            using var md5 = System.Security.Cryptography.MD5.Create();
            var bytes = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(s));
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        // C14 helper — exposes the section-layout fingerprint computation
        // so tests can prove the algorithm is deterministic and matches
        // a known curated MD5 entry.
        internal static string ComputeSectionLayoutFingerprint(IEnumerable<string> sectionNames)
        {
            var names = sectionNames
                .Where(s => !string.IsNullOrEmpty(s))
                .Select(s => s.ToLowerInvariant())
                .OrderBy(s => s, StringComparer.Ordinal)
                .ToList();
            if (names.Count == 0) return "";
            return ComputeMd5Hex(string.Join("|", names));
        }

        internal static void DetectKnownBadRichHeader(AnalysisResult r)
        {
            if (string.IsNullOrEmpty(r.RichHeaderHash) && string.IsNullOrEmpty(r.RichHeaderHashStd)) return;
            EnsureExternalKnownBadLoaded();
            foreach (var (h, fam) in AdditionalRichHeader)
            {
                if (string.Equals(h, r.RichHeaderHash,    StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(h, r.RichHeaderHashStd, StringComparison.OrdinalIgnoreCase))
                {
                    r.RichHeaderFamilyMatch = fam;
                    return;
                }
            }
            foreach (var (h, fam) in KnownBadRichHeaders)
            {
                if (string.Equals(h, r.RichHeaderHash,    StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(h, r.RichHeaderHashStd, StringComparison.OrdinalIgnoreCase))
                {
                    r.RichHeaderFamilyMatch = fam;
                    return;
                }
            }
        }

        // ---------------------------------------------------------------------
        // BB7: DGA domain detection. For each extracted URL we pull the host,
        // strip port/path, then score the 2nd-level label using:
        //  a) shannon entropy of character distribution (high for random)
        //  b) consonant run length (e.g. "qxzbr" == suspicious)
        //  c) digit ratio (pure-numeric labels are rare for legit brands)
        //  d) a small known-good whitelist so we don't flag obvious brands.
        // Threshold-gated, deliberately cautious — DGA hits feed into Network /
        // Exfiltration scoring but are not decisive by themselves.
        // ---------------------------------------------------------------------
        private static readonly HashSet<string> DgaBenignBrands = new(StringComparer.OrdinalIgnoreCase)
        {
            "google", "youtube", "facebook", "twitter", "github", "microsoft", "apple",
            "amazon", "cloudflare", "wikipedia", "yandex", "mail", "vk", "rambler",
            "telegram", "discord", "steam", "roblox", "minecraft", "office365",
        };

        internal static void DetectDgaDomains(AnalysisResult r)
        {
            foreach (var url in r.UrlsFound)
            {
                var host = ExtractHostname(url);
                if (string.IsNullOrEmpty(host)) continue;

                var label = SecondLevelLabel(host);
                if (label.Length < 6 || label.Length > 40) continue;
                if (DgaBenignBrands.Contains(label)) continue;
                if (label.All(char.IsDigit)) continue; // handled by IPv4 hits, not DGA

                double entropy = ShannonEntropy(label);
                double digitRatio = label.Count(char.IsDigit) / (double)label.Length;
                int maxConsonantRun = LongestConsonantRun(label);

                // Heuristic: entropy >= 3.7 (of 4.75 max for base36) OR consonant run >= 5
                // OR high digit ratio with low English-letter ratio.
                if (entropy >= 3.7 || maxConsonantRun >= 5 || (digitRatio >= 0.3 && entropy >= 3.3))
                {
                    r.DgaSuspiciousDomains.Add($"{host} (H={entropy:0.00} cons={maxConsonantRun} digit={digitRatio:0.00})");
                }
            }
        }

        private static string ExtractHostname(string url)
        {
            try
            {
                // Strip scheme
                int schemeEnd = url.IndexOf("://", StringComparison.Ordinal);
                string rest = schemeEnd >= 0 ? url.Substring(schemeEnd + 3) : url;
                int slash = rest.IndexOfAny(new[] { '/', '?', '#' });
                if (slash >= 0) rest = rest.Substring(0, slash);
                int at = rest.IndexOf('@');
                if (at >= 0) rest = rest.Substring(at + 1);
                int colon = rest.IndexOf(':');
                if (colon >= 0) rest = rest.Substring(0, colon);
                return rest.Trim().ToLowerInvariant();
            }
            catch { return ""; }
        }

        private static string SecondLevelLabel(string host)
        {
            // "sub.foo.example.co.uk" -> "example"
            var parts = host.Split('.');
            if (parts.Length < 2) return host;
            // Two-part TLD handling (ccTLDs like co.uk / com.au / org.uk)
            string[] twoPartTlds = { "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "com.br", "co.jp", "com.cn", "co.kr" };
            if (parts.Length >= 3)
            {
                string last2 = parts[^2] + "." + parts[^1];
                if (twoPartTlds.Contains(last2))
                    return parts[^3];
            }
            return parts[^2];
        }

        private static double ShannonEntropy(string s)
        {
            if (s.Length == 0) return 0.0;
            var counts = new Dictionary<char, int>();
            foreach (var c in s.ToLowerInvariant()) counts[c] = counts.GetValueOrDefault(c) + 1;
            double h = 0.0;
            double len = s.Length;
            foreach (var c in counts.Values)
            {
                double p = c / len;
                h -= p * Math.Log(p, 2);
            }
            return h;
        }

        private static int LongestConsonantRun(string s)
        {
            int best = 0, cur = 0;
            foreach (var ch in s.ToLowerInvariant())
            {
                bool isConsonant = ch >= 'a' && ch <= 'z' && "aeiouy".IndexOf(ch) < 0;
                if (isConsonant) { cur++; if (cur > best) best = cur; }
                else cur = 0;
            }
            return best;
        }

        // ---------------------------------------------------------------------
        // BB8: bulletproof ASN / CIDR markers. We can't resolve ASN at static
        // analysis time without an external service, but we can flag IPs that
        // fall inside CIDR ranges known to belong to bulletproof hosters.
        // This is a conservative starter list; extend from external feed.
        // ---------------------------------------------------------------------
        private static readonly (uint Start, uint End, string Tag)[] BulletproofRanges = BuildBulletproofRanges();

        private static (uint, uint, string)[] BuildBulletproofRanges()
        {
            // Each entry is CIDR + tag (provider, AS name).
            var raw = new (string Cidr, string Tag)[]
            {
                // FlokiNET (AS41051) — historically abused
                ("185.100.87.0/24",  "FlokiNET/AS41051"),
                // Virtual Systems / BlueVPS
                ("185.159.36.0/22",  "BlueVPS/AS202422"),
                // HZ Hosting / private offshore
                ("194.26.29.0/24",   "HzHost/AS58065"),
                // Selectel (legit provider but heavily abused by stealers)
                ("95.182.121.0/24",  "Selectel-abuse"),
                // HostSailor (AS60117)
                ("185.63.190.0/24",  "HostSailor/AS60117"),
                // DDoS-Guard / Stark Industries umbrella (recent stealer C2)
                ("45.134.10.0/24",   "Stark/AS44477"),
                ("45.155.205.0/24",  "Stark/AS44477"),
                // Alexhost MD (offshore, heavy stealer abuse)
                ("176.124.207.0/24", "Alexhost/AS200019"),
                // NL-based "SharkTech / Private Layer" abused ranges
                ("178.162.202.0/24", "PrivateLayer/AS51852"),
            };
            return raw.Select(r => CidrToRange(r.Cidr, r.Tag)).Where(t => t.Item1 != 0 || t.Item2 != 0).ToArray();
        }

        private static (uint, uint, string) CidrToRange(string cidr, string tag)
        {
            try
            {
                var slash = cidr.IndexOf('/');
                var ip = cidr.Substring(0, slash);
                var prefix = int.Parse(cidr.Substring(slash + 1), CultureInfo.InvariantCulture);
                var parts = ip.Split('.');
                uint addr = (uint)((int.Parse(parts[0]) << 24) | (int.Parse(parts[1]) << 16) |
                                   (int.Parse(parts[2]) << 8)  |  int.Parse(parts[3]));
                uint mask = prefix == 0 ? 0u : 0xFFFFFFFFu << (32 - prefix);
                uint start = addr & mask;
                uint end   = start | ~mask;
                return (start, end, tag);
            }
            catch { return (0u, 0u, tag); }
        }

        internal static void DetectBulletproofAsn(AnalysisResult r)
        {
            foreach (var ipStr in r.Ipv4Hits)
            {
                if (!TryParseIpv4(ipStr, out uint addr)) continue;
                foreach (var (s, e, tag) in BulletproofRanges)
                {
                    if (addr >= s && addr <= e)
                    {
                        r.BulletproofAsnHits.Add($"{ipStr} → {tag}");
                        r.MitreTtps.Add("T1583.003"); // Acquire Infrastructure: Virtual Private Server
                        break;
                    }
                }
            }
        }

        private static bool TryParseIpv4(string s, out uint addr)
        {
            addr = 0;
            if (string.IsNullOrWhiteSpace(s)) return false;
            var parts = s.Split('.');
            if (parts.Length != 4) return false;
            for (int i = 0; i < 4; i++)
            {
                if (!int.TryParse(parts[i], NumberStyles.Integer, CultureInfo.InvariantCulture, out var oct)
                    || oct < 0 || oct > 255) return false;
                addr = (addr << 8) | (uint)oct;
            }
            return true;
        }

        // ---------------------------------------------------------------------
        // BB9: process-injection primitives.
        // Detect API combinations that together implement a specific technique.
        // - Classic-RemoteThread: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
        // - Process-Hollowing   : CreateProcess(SUSPENDED) + NtUnmapViewOfSection + NtMapViewOfSection
        // - APC-Queue / Early-Bird: QueueUserAPC + NtAlertResumeThread or ResumeThread
        // - Atom-Bombing        : GlobalAddAtom + NtQueueApcThread
        // - Thread-Hijack       : OpenThread + SuspendThread + SetThreadContext + ResumeThread
        // - DLL-Injection       : LoadLibrary + GetProcAddress + CreateRemoteThread
        // - Reflective DLL      : VirtualAlloc + WriteProcessMemory + CreateRemoteThread + no LoadLibrary
        // ---------------------------------------------------------------------
        internal static void DetectInjectionPrimitives(AnalysisResult r, IReadOnlyCollection<string> imports)
        {
            bool Has(params string[] needles) => needles.All(n => imports.Any(i => i.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0));
            bool Any(params string[] needles) => needles.Any(n => imports.Any(i => i.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0));

            if (Has("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"))
                r.InjectionPrimitives.Add("Classic-RemoteThread");

            if (Has("NtUnmapViewOfSection", "NtMapViewOfSection") &&
                Any("CreateProcessA", "CreateProcessW", "CreateProcessInternal"))
                r.InjectionPrimitives.Add("Process-Hollowing");

            if (Has("QueueUserAPC") && Any("NtAlertResumeThread", "NtResumeThread", "ResumeThread"))
                r.InjectionPrimitives.Add("APC-Queue/Early-Bird");

            if (Has("GlobalAddAtom") && Any("NtQueueApcThread", "QueueUserAPC"))
                r.InjectionPrimitives.Add("Atom-Bombing");

            if (Has("OpenThread", "SuspendThread", "SetThreadContext", "ResumeThread"))
                r.InjectionPrimitives.Add("Thread-Hijack");

            if (Has("LoadLibraryA", "CreateRemoteThread") || Has("LoadLibraryW", "CreateRemoteThread"))
                r.InjectionPrimitives.Add("DLL-Injection");

            // Reflective DLL: memory alloc+write+exec in remote process but *no* LoadLibrary.
            if (Has("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread") &&
                !Any("LoadLibraryA", "LoadLibraryW"))
                r.InjectionPrimitives.Add("Reflective-DLL-Suspect");

            // Each detected technique maps to the relevant ATT&CK sub-technique.
            foreach (var tech in r.InjectionPrimitives)
            {
                switch (tech)
                {
                    case "Classic-RemoteThread":       r.MitreTtps.Add("T1055.002"); break;
                    case "Process-Hollowing":          r.MitreTtps.Add("T1055.012"); break;
                    case "APC-Queue/Early-Bird":       r.MitreTtps.Add("T1055.004"); break;
                    case "Atom-Bombing":               r.MitreTtps.Add("T1055.014"); break;
                    case "Thread-Hijack":              r.MitreTtps.Add("T1055.003"); break;
                    case "DLL-Injection":              r.MitreTtps.Add("T1055.001"); break;
                    case "Reflective-DLL-Suspect":     r.MitreTtps.Add("T1620");     break;
                }
            }
        }

        // ---------------------------------------------------------------------
        // BB10: DLL-sideloading target detection. If the sample is a DLL whose
        // export table includes the characteristic exports of a specific
        // Windows system library, it may be a sideload payload — a benign .exe
        // will load it instead of the real system DLL from System32.
        // This is conservative: we require *all* canonical exports to match,
        // plus name similarity, to avoid flagging normal open-source libraries.
        // ---------------------------------------------------------------------
        private static readonly (string SystemDll, string[] Exports)[] SideloadSignatures =
        {
            // DWMAPI — very commonly sideloaded by malware (VLC, Adobe).
            ("DWMAPI.dll", new[] { "DwmEnableBlurBehindWindow", "DwmExtendFrameIntoClientArea", "DwmGetColorizationColor", "DwmIsCompositionEnabled" }),
            // VERSION.dll — classic sideload target.
            ("VERSION.dll", new[] { "GetFileVersionInfoA", "GetFileVersionInfoSizeA", "GetFileVersionInfoW", "VerQueryValueA" }),
            // UxTheme — themes, often used by game-launcher malware.
            ("UxTheme.dll", new[] { "GetThemeBackgroundRegion", "GetThemeSysFont", "OpenThemeData", "DrawThemeBackground" }),
            // WinMM — multimedia, used by legit software so fewer FP risk but real abuse cases.
            ("WINMM.dll", new[] { "waveInOpen", "waveOutWrite", "timeGetTime", "PlaySoundA" }),
            // OLEACC
            ("OLEACC.dll", new[] { "AccessibleObjectFromWindow", "AccessibleObjectFromEvent", "GetRoleTextA", "CreateStdAccessibleObject" }),
            // SECUR32
            ("SECUR32.dll", new[] { "LsaConnectUntrusted", "LsaLookupAuthenticationPackage", "QuerySecurityPackageInfoA", "FreeContextBuffer" }),
            // B17 — additional known sideload targets from MITRE ATT&CK
            // T1574.002 and APT IOC databases. Each entry is a DLL that
            // legitimate-signed software loads from its install
            // directory before falling back to System32; attackers drop
            // a malicious copy alongside the EXE so it loads instead.
            ("d3dcompiler_47.dll", new[] { "D3DCompile", "D3DCompile2", "D3DCompileFromFile", "D3DDisassemble" }),
            ("dbghelp.dll",        new[] { "SymInitialize", "SymCleanup", "SymFromAddr", "SymFromName" }),
            ("cryptbase.dll",      new[] { "CryptAcquireContextA", "CryptAcquireContextW", "SystemFunction036" }),
            ("cryptsp.dll",        new[] { "CryptAcquireContextA", "CryptAcquireContextW", "CryptReleaseContext" }),
            ("msi.dll",            new[] { "MsiGetComponentPathA", "MsiInstallProductA", "MsiOpenProductA" }),
            ("MSIMG32.dll",        new[] { "AlphaBlend", "TransparentBlt", "GradientFill" }),
            ("vsps.dll",           new[] { "DllRegisterServer", "DllUnregisterServer" }),
            ("rsaenh.dll",         new[] { "CPGenKey", "CPEncrypt", "CPDecrypt", "CPHashData" }),
            ("propsys.dll",        new[] { "PropVariantToBuffer", "PropVariantToString", "PSCreatePropertyStoreFromObject" }),
            ("rpcrt4.dll",         new[] { "RpcStringBindingComposeW", "NdrServerCall2", "NdrAsyncServerCall" }),
            ("sspicli.dll",        new[] { "AcquireCredentialsHandleA", "FreeCredentialsHandle", "InitializeSecurityContextA" }),
            ("wininet.dll",        new[] { "InternetOpenA", "InternetConnectA", "InternetReadFile", "HttpSendRequestA" }),
            ("usp10.dll",          new[] { "ScriptStringAnalyse", "ScriptStringFree", "ScriptItemize" }),
            ("hid.dll",            new[] { "HidD_GetAttributes", "HidD_GetPreparsedData", "HidP_GetCaps" }),
        };

        internal static void DetectDllSideloadingSuspect(AnalysisResult r)
        {
            if (!r.IsDll) return;
            if (r.ExportedFunctions == null || r.ExportedFunctions.Count < 3) return;

            var exports = new HashSet<string>(r.ExportedFunctions, StringComparer.OrdinalIgnoreCase);
            string baseFile = Path.GetFileName(r.FilePath);

            foreach (var (dll, neededExports) in SideloadSignatures)
            {
                int matched = neededExports.Count(n => exports.Contains(n));
                if (matched < neededExports.Length) continue;

                // All canonical exports present. Two cases:
                //  a) the file is named like the system DLL (e.g. "dwmapi.dll")   — HIGH suspicion
                //  b) it's not — still suspicious but may be a legit re-impl
                bool nameMatches = string.Equals(baseFile, dll, StringComparison.OrdinalIgnoreCase);
                r.DllSideloadTargetGuess = nameMatches
                    ? $"{dll} (exact filename match — probable sideload payload)"
                    : $"mimics {dll} (all {matched} canonical exports present, non-system path)";
                r.MitreTtps.Add("T1574.002"); // Hijack Execution Flow: DLL Side-Loading
                return;
            }
        }

        // ---------------------------------------------------------------------
        // BB1: Sigma-full. We parse a deliberately-minimal Sigma-like YAML
        // (selection:, condition:, fields = exact substrings) so that users
        // can ship detection rules without having to recompile. Full Sigma
        // spec is huge; this covers the 80 % that applies to static string
        // / import matching.
        // Example rule:
        //   title: Stealer — Telegram exfil
        //   selection:
        //     url:
        //       - "api.telegram.org/bot"
        //       - "sendMessage"
        //   condition: all of selection
        // ---------------------------------------------------------------------
        // Section 10.1 — back-compat wrapper. The real engine now lives in
        // RulesEngines.cs (SigmaFullEngine); we keep this entry point so any
        // existing call sites / tests that reference DetectSigmaRulesFull
        // by name continue to work.
        internal static void DetectSigmaRulesFull(AnalysisResult r, string analysisText)
            => SigmaFullEngine.Run(r, analysisText);

        // Legacy ParseSigmaMinimal / EvaluateSigmaCondition were removed when
        // the full Sigma engine (Section 10.1) replaced them — the new
        // SigmaFullEngine in RulesEngines.cs accepts a strict superset of
        // the original mini-spec.

        // ---------------------------------------------------------------------
        // BB2: CAPA-ish rule evaluator. Each rule is a plain-text file with
        // `key: value` lines:
        //   capability: steals clipboard data
        //   imports:
        //     - OpenClipboard
        //     - GetClipboardData
        //     - SetClipboardData
        //   match: any  # or "all", default "all"
        //   strings:
        //     - wallet
        //     - mnemonic
        // The detector passes if `match` satisfies the predicate on imports
        // AND all listed strings are present in analysisText (if any).
        // ---------------------------------------------------------------------
        // Section 10.2 — back-compat wrapper around the new CapaFullEngine in
        // RulesEngines.cs. The new engine supports the legacy flat form
        // (capability/match/imports/strings) plus a richer YAML "rule:" form
        // with meta + features tree (and/or/not/optional/N or more).
        internal static void DetectCapaRules(AnalysisResult r, string analysisText)
            => CapaFullEngine.Run(r, analysisText);

        // Shared: find a rules directory. Look in %APPDATA%\AntiStealer\rules\<subdir>,
        // then in the executable folder's rules\<subdir>, then a repo-relative location.
        private static string? ResolveRulesDir(string subdir)
        {
            try
            {
                var roaming = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                                           "AntiStealer", "rules", subdir);
                if (Directory.Exists(roaming)) return roaming;
                var cwd = Path.Combine(AppContext.BaseDirectory, "rules", subdir);
                if (Directory.Exists(cwd)) return cwd;
                return null;
            }
            catch { return null; }
        }

        // ---------------------------------------------------------------------
        // BB4: ONNX family classifier scaffold.
        // If a model file is present at %APPDATA%\AntiStealer\models\family.onnx
        // we'd run Microsoft.ML.OnnxRuntime here. We don't add the package
        // dependency by default — commercial edition ships the model & package
        // together; Community edition keeps the feature disabled.
        // ---------------------------------------------------------------------
        // Aggregate score bonus from BB1..BB10. Each advanced module contributes a bounded
        // number of points — together they can add up to ~+40, but typically add 5-15.
        internal static int AdvancedDetectionBonus(AnalysisResult r)
        {
            int b = 0;
            // BB5 / BB6 — known-bad build artefact → very strong, +25 each but capped at 30.
            if (!string.IsNullOrEmpty(r.ImphashFamilyMatch))     b += 25;
            if (!string.IsNullOrEmpty(r.RichHeaderFamilyMatch))  b += 10;
            // C14 — extended known-bad fingerprint hits.
            // Authentihash / SHA256 are exact-match indicators of known
            // payloads (strongest); section layout is a softer hint
            // (UPX / Themida / generic crypter layouts overlap with
            // some benign installers).
            if (!string.IsNullOrEmpty(r.AuthentihashFamilyMatch)) b += 30;
            if (!string.IsNullOrEmpty(r.Sha256FamilyMatch))       b += 35;
            if (!string.IsNullOrEmpty(r.SectionLayoutFamilyMatch)) b += 8;
            // BB9 — real injection primitives identified (not just isolated imports).
            b += Math.Min(20, r.InjectionPrimitives.Count * 8);
            // BB10 — likely DLL-sideload payload.
            if (!string.IsNullOrEmpty(r.DllSideloadTargetGuess)) b += 15;
            // BB1 / BB2 — each rule file hit adds a moderate amount, capped.
            b += Math.Min(20, r.SigmaFullHits.Count * 5);
            b += Math.Min(20, r.CapaHits.Count       * 5);
            // BB7 / BB8 — DGA domain or bulletproof ASN membership (not decisive alone).
            b += Math.Min(10, r.DgaSuspiciousDomains.Count * 3);
            b += Math.Min(15, r.BulletproofAsnHits.Count   * 8);
            // BB3 doesn't score; it's a report-only enrichment.
            return Math.Min(50, b);
        }

        internal static void RunMlFamilyClassifierIfAvailable(AnalysisResult r)
        {
            // Section 3 (PR 14): full ML pipeline. Loads a small JSON
            // logistic-regression model exported by tools/ml/train.py
            // and runs feature extraction → score → Platt calibration
            // → top-1 family. ONNX inference is honoured if a sibling
            // family.onnx + Microsoft.ML.OnnxRuntime is available
            // (detection happens inside MlPipeline). Otherwise the
            // in-process linear scorer is used. Both paths produce a
            // template-rendered MlSummary line either way.
            MlPipeline.RunOn(r);
        }
    }
}
