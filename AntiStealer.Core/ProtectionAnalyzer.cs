// PR 15 — Section 4 — Stages P1-P4 + P12: protector / packer
// suspicion engine + dynamic API resolver detection + static
// anti-analysis indicators + limited_static_visibility status.
//
// Themida / VMProtect / Enigma and friends specifically eliminate
// most of the surface a string-based scanner relies on: imports
// are reduced to LoadLibrary / GetProcAddress, code is encrypted
// or virtualized into a stub section, normal section names are
// renamed or scrambled, debug / version metadata is stripped.
// Trying to "match the protector by name" is a losing battle.
//
// What does still survive is the PE STRUCTURE — high entropy on
// the entry-point section, a very small import table, an
// abnormal section layout, optional TLS callbacks, optional RWX
// sections, a large encrypted overlay. None of these is itself
// proof of malice (legitimate software DOES use Themida), but
// combined with a Lua loader / SA-MP context / DLL side-load
// pair, they push the verdict to HIGH.
//
// This module:
//   P1  fills r.Protection (BinaryProtectionInfo) with a packed
//       score, structural flags, list of reasons.
//   P2  takes a guess at the protector family ("Themida-like /
//       VM-protected", "UPX", "MPRESS", "ConfuserEx-like", ...)
//       without making the verdict depend on the guess.
//   P3  detects dynamic API resolver imports (few imports + only
//       LoadLibrary / GetProcAddress / Virtual* + import-table
//       reconstruction patterns).
//   P4  detects static anti-analysis indicators (IsDebuggerPresent,
//       CheckRemoteDebuggerPresent, NtQueryInformationProcess,
//       OutputDebugString, rdtsc, VirtualBox / VMware / Sandboxie
//       strings).
//   P12 when r.Protection.IsProtected is set but no decisive
//       behavioral evidence has accumulated, mark the result
//       with AnalysisStatus = "limited_static_visibility" so the
//       UI can show "packed but behavior unknown — dynamic memory
//       scan recommended".

using System;
using System.Collections.Generic;
using System.Linq;

namespace AntiStealerOneExe
{
    /// <summary>
    /// Structural protection / packer fingerprint of a PE file.
    /// Populated by <see cref="ProtectionAnalyzer.Compute"/>.
    /// </summary>
    public sealed class BinaryProtectionInfo
    {
        /// <summary>True when the packed score crosses the 60 threshold.</summary>
        public bool          IsProtected     { get; set; }
        /// <summary>
        /// Best-effort family guess. NEVER feeds the verdict on its
        /// own — only used in human-readable explanations.
        /// </summary>
        public string?       ProtectorGuess  { get; set; }
        /// <summary>0-100 packed-suspicion score.</summary>
        public int           PackedScore     { get; set; }
        /// <summary>
        /// Human-readable structural reasons that contributed to
        /// the score. Used in the report and in capability graphs.
        /// </summary>
        public List<string>  Reasons         { get; set; } = new();
        // Structural flags (mirror of the indicators that
        // contributed to the score, useful for downstream rules).
        public bool          HasHighEntropyCode      { get; set; }
        public bool          HasRwxSection           { get; set; }
        public bool          HasFewImports           { get; set; }
        public bool          HasDynamicApiResolution { get; set; }
        public bool          HasSuspiciousTlsCallback{ get; set; }
        public bool          HasLargeOverlay         { get; set; }
        public bool          HasPackerSectionName    { get; set; }
        public bool          HasAntiDebugApis        { get; set; }
        public bool          HasAntiVmStrings        { get; set; }
        public List<string>  AntiAnalysisHits        { get; set; } = new();
    }

    public sealed partial class AnalysisResult
    {
        // P1 — structural protection / packer fingerprint.
        public BinaryProtectionInfo Protection { get; set; } = new();
        // P12 — analyzer-level status indicator. "ok" (default)
        // when static analysis fully observed the file; otherwise
        // "limited_static_visibility" when the file is packed /
        // protected and no decisive behavioral evidence was
        // collected, which the UI can use to recommend dynamic
        // memory scanning.
        public string AnalysisStatus        { get; set; } = "ok";
        public string? RecommendedNextStage { get; set; }
    }

    public static class ProtectionAnalyzer
    {
        // P2 — known packer / protector section-name hints. We map
        // a hit to a best-effort family name; presence of more
        // than one strong indicator collapses to "Themida-like /
        // VM-protected" since their common defining trait is heavy
        // virtualization, not the specific tool used.
        private static readonly (string Marker, string Family)[] SectionFamilyHints =
        {
            ("UPX",         "UPX"),
            (".themida",    "Themida"),
            (".oreans",     "Themida / WinLicense"),
            (".vmp",        "VMProtect"),
            (".aspack",     "ASPack"),
            (".mpress",     "MPRESS"),
            (".pec1",       "PECompact"),
            (".pec2",       "PECompact"),
            ("Enigma",      "Enigma"),
            (".obsidium",   "Obsidium"),
            (".confuser",   "ConfuserEx"),
            (".smart",      "SmartAssembly"),
            (".reactor",    ".NET Reactor"),
            (".eaz",        "Eazfuscator"),
        };

        // Imports that are characteristic of dynamic API resolvers.
        // Packed code typically calls LoadLibrary + GetProcAddress
        // in a loop after unpacking; if those are essentially the
        // only imports, that's a strong packer signal (P3).
        private static readonly string[] ResolverApis =
        {
            "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA",
            "LoadLibraryExW", "GetProcAddress", "GetModuleHandleA",
            "GetModuleHandleW", "VirtualAlloc", "VirtualProtect",
            "VirtualAllocEx", "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory", "LdrLoadDll", "LdrGetProcedureAddress",
        };
        // P4 — static anti-debug / anti-analysis indicators.
        private static readonly string[] AntiDebugApis =
        {
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "OutputDebugStringA",
            "OutputDebugStringW", "FindWindowA", "FindWindowW",
            "CreateToolhelp32Snapshot", "Process32FirstW",
            "Process32NextW", "Process32First", "Process32Next",
            "GetTickCount", "GetTickCount64",
            "QueryPerformanceCounter", "ZwQueryInformationProcess",
            "DbgUiRemoteBreakin", "DbgBreakPoint",
            "NtSetInformationThread",
            "NtRaiseHardError",
        };
        private static readonly string[] AntiVmStrings =
        {
            "VirtualBox", "VBOX", "VBoxService", "VBoxTray",
            "VMware", "vmtoolsd", "VMwareService", "vboxguest",
            "Sandboxie", "SbieDll", "cuckoo", "cuckoomon",
            "wine_get_version",
            "QEMU", "Parallels",
        };

        // -----------------------------------------------------------------

        /// <summary>
        /// Fill <see cref="AnalysisResult.Protection"/> from the
        /// PE structural facts that are already on the result
        /// (imports, sections, overlay, entropy, ...). Safe to
        /// call multiple times — fully overwrites the previous
        /// Protection value.
        /// </summary>
        public static void Compute(AnalysisResult r)
        {
            if (r == null) return;
            // Only meaningful for files we identified as a PE.
            var fam = r.FormatFamily ?? string.Empty;
            bool isPe = r.IsDll || r.FileType?.StartsWith("PE", StringComparison.OrdinalIgnoreCase) == true ||
                        fam.StartsWith("PE", StringComparison.OrdinalIgnoreCase) ||
                        fam.Equals("PE-DLL-ASI", StringComparison.OrdinalIgnoreCase);
            if (!isPe) return;

            var p = new BinaryProtectionInfo();
            int score = 0;

            // High-entropy executable section. We don't have an
            // is-executable bit per section name in the result, so
            // we use a permissive heuristic: any section with
            // entropy >= 7.2 contributes, with extra weight if the
            // name looks like a code section (.text / startup /
            // CODE) or matches a known packer section family.
            if (r.SectionEntropy != null)
            {
                foreach (var kv in r.SectionEntropy)
                {
                    if (kv.Value >= 7.2)
                    {
                        p.HasHighEntropyCode = true;
                        p.Reasons.Add($"section:{kv.Key}:entropy={kv.Value:0.00}");
                        score += 18;
                        break;
                    }
                }
            }

            // RWX section. ExecutableWritableSections is already
            // tracked by Analyzer.cs (executable + writable bit).
            if (r.ExecutableWritableSections != null &&
                r.ExecutableWritableSections.Count > 0)
            {
                p.HasRwxSection = true;
                p.Reasons.Add("section:rwx=" +
                              string.Join(",", r.ExecutableWritableSections.Take(4)));
                score += 18;
            }

            // Few imports — strong packer signal. We deliberately
            // use a tight threshold (8) because reasonable libc-
            // wrapped binaries typically have many more.
            int importCount = r.ImportedApis?.Count ?? 0;
            if (importCount > 0 && importCount <= 8)
            {
                p.HasFewImports = true;
                p.Reasons.Add($"imports:count={importCount}");
                score += 20;
            }
            else if (importCount > 0 && importCount <= 16)
            {
                // Borderline — still suspicious but a softer signal.
                p.Reasons.Add($"imports:count={importCount}");
                score += 8;
            }

            // P3 — dynamic API resolver pattern: of the few imports
            // that exist, most/all of them are LoadLibrary /
            // GetProcAddress / Virtual* / Nt* primitives.
            if (importCount > 0)
            {
                int resolverHits = ResolverApis.Count(api =>
                    r.ImportedApis!.Contains(api, StringComparer.OrdinalIgnoreCase));
                if (resolverHits >= 2 && resolverHits * 2 >= importCount)
                {
                    p.HasDynamicApiResolution = true;
                    p.Reasons.Add($"imports:resolver={resolverHits}/{importCount}");
                    score += 22;
                }
            }

            // TLS callback section.
            if (r.SectionNames != null &&
                r.SectionNames.Any(s => s.Equals(".tls",
                                                  StringComparison.OrdinalIgnoreCase)))
            {
                p.HasSuspiciousTlsCallback = true;
                p.Reasons.Add("section:.tls");
                score += 12;
            }

            // Large, high-entropy overlay. Packers (especially
            // installers + Themida overlays) often park the real
            // payload there.
            if (r.OverlaySize > 512 * 1024)
            {
                p.HasLargeOverlay = true;
                p.Reasons.Add($"overlay:size={r.OverlaySize}");
                score += 12;
            }

            // P2 — packer-family section-name marker.
            if (r.SectionNames != null)
            {
                foreach (var (marker, family) in SectionFamilyHints)
                {
                    if (r.SectionNames.Any(s => s.Contains(marker,
                                                  StringComparison.OrdinalIgnoreCase)))
                    {
                        p.HasPackerSectionName = true;
                        p.ProtectorGuess ??= family;
                        p.Reasons.Add("section-name:" + marker);
                        score += 15;
                        break;
                    }
                }
            }

            // .NET protectors / obfuscators — these were already
            // surfaced by DetectDotNetObfuscators(); copy any
            // family hit into the protection guess so the report
            // can show a coherent ProtectorGuess.
            if (r.IsDotNetLikely && p.ProtectorGuess == null)
            {
                var dotnetHints = ((IEnumerable<string>?)r.PackerHints ?? Array.Empty<string>())
                    .Concat((IEnumerable<string>?)r.DotNetObfuscatorHits ?? Array.Empty<string>())
                    .ToList();
                if (dotnetHints.Any(h => h.IndexOf("ConfuserEx",
                                                 StringComparison.OrdinalIgnoreCase) >= 0))
                    p.ProtectorGuess = "ConfuserEx";
                else if (dotnetHints.Any(h => h.IndexOf("SmartAssembly",
                                                 StringComparison.OrdinalIgnoreCase) >= 0))
                    p.ProtectorGuess = "SmartAssembly";
                else if (dotnetHints.Any(h => h.IndexOf("Reactor",
                                                 StringComparison.OrdinalIgnoreCase) >= 0))
                    p.ProtectorGuess = ".NET Reactor";
                else if (dotnetHints.Any(h => h.IndexOf("Eazfuscator",
                                                 StringComparison.OrdinalIgnoreCase) >= 0))
                    p.ProtectorGuess = "Eazfuscator";
            }

            // P4 — anti-debug / anti-vm static surface.
            if (r.ImportedApis != null)
            {
                foreach (var api in AntiDebugApis)
                    if (r.ImportedApis.Contains(api, StringComparer.OrdinalIgnoreCase))
                        p.AntiAnalysisHits.Add("api:" + api);
            }
            if (r.StringHits != null)
            {
                foreach (var s in AntiVmStrings)
                    if (r.StringHits.Any(x => x != null &&
                                              x.IndexOf(s,
                                                StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        p.AntiAnalysisHits.Add("string:" + s);
                        p.HasAntiVmStrings = true;
                    }
            }
            if (p.AntiAnalysisHits.Count >= 1)
            {
                p.HasAntiDebugApis = p.AntiAnalysisHits.Any(h =>
                    h.StartsWith("api:", StringComparison.Ordinal));
                // Anti-debug alone is NOT proof of malware (lots of
                // legitimate copy-protection uses it) — keep the
                // contribution small.
                score += Math.Min(10, p.AntiAnalysisHits.Count * 3);
            }

            // Cap into 0..100 and decide on the protection flag.
            p.PackedScore = Math.Min(100, score);
            // The 60 cut-off is intentional: we want the file to
            // show *at least two* of the structural anomalies above
            // before we call it protected.
            p.IsProtected = p.PackedScore >= 60;

            // If the file is clearly protected but we couldn't
            // pin down a family, label it generically. The
            // operator can still see the structural reasons.
            if (p.IsProtected && p.ProtectorGuess == null)
                p.ProtectorGuess = "Themida-like / VM-protected";

            r.Protection = p;

            // P12 — limited static visibility. When the binary is
            // protected but we have NOT collected any of the
            // decisive behavioral evidence (no exfil sink, no
            // credential targets, no YARA hits, no Lua chain, no
            // known-bad fingerprint), mark the report so the UI
            // can surface "packed but behavior unknown" as opposed
            // to "clean".
            bool hasBehavior =
                r.AppliedFloors.Count > 0 ||
                r.YaraHits.Count > 0 ||
                r.BrowserStealerIndicators.Count > 0 ||
                r.CryptoWalletHits.Count > 0 ||
                r.TelegramExfilEndpoints.Count > 0 ||
                r.DiscordTokenHits.Count > 0 ||
                r.LuaThreatHits.Count > 0 ||
                r.LuaDownloadAndLoadChain ||
                r.LuaCredentialExfilChain ||
                !string.IsNullOrEmpty(r.ImphashFamilyMatch);
            if (p.IsProtected && !hasBehavior)
            {
                r.AnalysisStatus       = "limited_static_visibility";
                r.RecommendedNextStage = "dynamic-memory-scan";
            }
        }
    }
}
