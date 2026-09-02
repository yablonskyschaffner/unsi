// PR 15 — Section 4 — Stages P8 + P9 + P10:
//   P8  — .NET DLL inspector (#US strings, obfuscated-name ratio,
//          mixed-mode / NetCore module flags).
//   P9  — structured YARA hit details with explicit source tagging
//          (file / memory / resource / decoded / child).
//   P10 — capability graph + FinalVerdict structure that callers
//          (UI, JSON report, CLI summary) can consume directly.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text;

namespace AntiStealerOneExe
{
    // -----------------------------------------------------------------
    // P9 — structured YARA hit details.
    // -----------------------------------------------------------------

    public sealed class YaraHitDetail
    {
        /// <summary>
        /// "file" (default), "memory", "resource", "decoded", "child".
        /// </summary>
        public string Source   { get; set; } = "file";
        public string RuleFile { get; set; } = string.Empty;
        public string RuleName { get; set; } = string.Empty;
        /// <summary>
        /// Where in the file the hit was observed (when known).
        /// E.g. "prefix", "overlay", "section:.text", "resource:11".
        /// </summary>
        public string Region   { get; set; } = string.Empty;
    }

    // -----------------------------------------------------------------
    // P10 — final verdict structure consumed by the UI / report / CLI.
    // -----------------------------------------------------------------

    public sealed class FinalVerdict
    {
        /// <summary>
        /// One of: <c>clean</c>, <c>low</c>, <c>medium</c>, <c>high</c>,
        /// <c>critical</c>.
        /// </summary>
        public string Verdict       { get; set; } = "clean";
        /// <summary>0..100 — calibrated confidence in the verdict.</summary>
        public int    Confidence    { get; set; }
        /// <summary>
        /// Human-readable single-line reason, suitable for a CLI
        /// summary or report header.
        /// </summary>
        public string Reason        { get; set; } = string.Empty;
        /// <summary>
        /// Capabilities that exceeded the publish threshold (>= 30).
        /// Ordered descending by score.
        /// </summary>
        public List<string> Capabilities { get; set; } = new();
        /// <summary>
        /// AppliedFloors that fired, in the order Score() applied
        /// them. Surfaced verbatim so operators can see WHY the
        /// verdict crossed a particular band.
        /// </summary>
        public List<string> Floors      { get; set; } = new();
        /// <summary>
        /// Structural protector / packer guess, copied from
        /// Protection.ProtectorGuess (when set). Helps operators
        /// triage packed-but-behavior-unknown samples.
        /// </summary>
        public string?      ProtectorGuess { get; set; }
        /// <summary>
        /// Mirrors r.AnalysisStatus ("ok" / "limited_static_visibility").
        /// </summary>
        public string       AnalysisStatus       { get; set; } = "ok";
        public string?      RecommendedNextStage { get; set; }
    }

    public sealed partial class AnalysisResult
    {
        // P9 — structured hit details (Source / RuleFile / RuleName /
        // Region). Always parallels the legacy r.YaraHits string list;
        // tests / consumers may use whichever they prefer.
        public List<YaraHitDetail> YaraHitDetails { get; set; } = new();
        // P10 — capability graph final verdict, recomputed by
        // FinalizeFlags() after Score() / MaliciousConfidence.
        public FinalVerdict Verdict { get; set; } = new();
        // P8 — .NET-specific extras.
        public List<string> DotNetUserStringHits     { get; set; } = new();
        public int          DotNetObfuscatedNameHits { get; set; }
        public int          DotNetMethodCount        { get; set; }
        public bool         DotNetHasCryptoStub      { get; set; }
    }

    // =================================================================

    public static class YaraHitTagger
    {
        /// <summary>
        /// Record a structured YARA hit + mirror it onto the legacy
        /// <see cref="AnalysisResult.YaraHits"/> string list. Safe
        /// to call multiple times; deduplicates on RuleFile+RuleName.
        /// </summary>
        public static void AddHit(AnalysisResult r,
                                  string source,
                                  string ruleFile,
                                  string ruleName,
                                  string region = "")
        {
            if (r == null) return;
            if (string.IsNullOrEmpty(ruleName)) return;
            source   ??= "file";
            ruleFile ??= string.Empty;

            // Dedup on legacy "<file>:<rule>" form.
            var legacy = string.IsNullOrEmpty(ruleFile)
                            ? ruleName
                            : $"{ruleFile}:{ruleName}";
            if (!r.YaraHits.Contains(legacy)) r.YaraHits.Add(legacy);

            // Push structured detail unless an exact duplicate is
            // already present.
            bool dup = r.YaraHitDetails.Any(d =>
                d.Source   == source   &&
                d.RuleFile == ruleFile &&
                d.RuleName == ruleName);
            if (!dup)
            {
                r.YaraHitDetails.Add(new YaraHitDetail
                {
                    Source   = source,
                    RuleFile = ruleFile,
                    RuleName = ruleName,
                    Region   = region ?? string.Empty,
                });
            }
        }
    }

    // =================================================================
    // P8 — .NET metadata inspector.
    // =================================================================

    public static class NetMetadataInspector
    {
        // Substrings that, when seen in the #US heap (user-strings),
        // are direct evidence of stealer behaviour. These are scanned
        // case-insensitively so that obfuscators that randomly change
        // case still match.
        private static readonly string[] SuspiciousUserStrings =
        {
            "Login Data", "Web Data", "Cookies", "Local State",
            "Discord", "leveldb",   "tdata",   "key_datas",
            "wallet.dat", "metamask","phantom", "exodus",
            "BIP39",      "Telegram","api.telegram.org",
            "discord.com/api/webhooks",
            "DPAPI",      "CryptUnprotectData",
            "VirtualAlloc","NtAllocateVirtualMemory",
        };

        /// <summary>
        /// Read the #US heap of a .NET PE and surface any
        /// suspicious user strings + a coarse obfuscation ratio.
        /// Silently no-ops on non-.NET files and on managed PEs we
        /// can't open. The implementation is bounded — at most
        /// 20 000 user strings are inspected.
        /// </summary>
        public static void Inspect(AnalysisResult r, string filePath)
        {
            if (r == null) return;
            if (!r.IsDotNetLikely) return;
            if (string.IsNullOrEmpty(filePath)) return;
            if (!File.Exists(filePath))         return;

            try
            {
                using var fs  = File.OpenRead(filePath);
                using var pe  = new PEReader(fs);
                if (!pe.HasMetadata) return;

                var mr = pe.GetMetadataReader();
                // ---- #US heap scan ------------------------------
                int idx = 1;
                int scanned = 0;
                while (scanned < 20_000)
                {
                    UserStringHandle h;
                    try
                    {
                        h = MetadataTokens.UserStringHandle(idx);
                    }
                    catch { break; }
                    string s;
                    try { s = mr.GetUserString(h); }
                    catch { break; }
                    if (s == null) break;
                    idx += 1 + Encoding.UTF8.GetByteCount(s);
                    scanned++;

                    if (s.Length == 0) continue;
                    foreach (var needle in SuspiciousUserStrings)
                    {
                        if (s.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            if (!r.DotNetUserStringHits.Contains(needle))
                                r.DotNetUserStringHits.Add(needle);
                            break;
                        }
                    }
                    if (r.DotNetUserStringHits.Count >= 64) break;
                }

                // ---- Method name obfuscation ratio --------------
                int methodCount = 0;
                int obfMethods  = 0;
                foreach (var mh in mr.MethodDefinitions)
                {
                    if (methodCount >= 4096) break;
                    methodCount++;
                    var md   = mr.GetMethodDefinition(mh);
                    var name = mr.GetString(md.Name);
                    if (string.IsNullOrEmpty(name)) continue;
                    // Heuristics for obfuscated names:
                    //  - single-char identifiers other than 'M' (the
                    //    common abbreviation), 'I', 'i'.
                    //  - non-ASCII (typical ConfuserEx output).
                    //  - <Module>Code, b__, m_, _Lambda$.
                    bool nonAscii = name.Any(ch => ch > 127);
                    bool shortRand = name.Length == 1
                                     && name[0] != 'M'
                                     && name[0] != 'I'
                                     && name[0] != 'i';
                    if (nonAscii || shortRand) obfMethods++;
                }
                r.DotNetMethodCount        = methodCount;
                r.DotNetObfuscatedNameHits = obfMethods;
                if (methodCount > 64 &&
                    obfMethods * 100 / Math.Max(1, methodCount) >= 35)
                {
                    // Strong evidence of obfuscation. Reflect it
                    // both in the .NET-specific hits and in the
                    // generic obfuscator list so existing reports
                    // pick it up.
                    if (!r.DotNetObfuscatorHits.Contains("ObfuscatedNames"))
                        r.DotNetObfuscatorHits.Add("ObfuscatedNames");
                }

                // ---- Crypto-stub heuristic ---------------------
                // ConfuserEx-style runtime decryption stubs leave
                // a "<Module>" type with a static .cctor that
                // touches Convert.FromBase64String / RijndaelManaged
                // / Cryptography. Cheap proxy: any method body in
                // a managed module that contains an entry-point
                // and uses these names.
                if (r.DotNetUserStringHits.Any(u =>
                    u.IndexOf("Cryptography", StringComparison.Ordinal) >= 0 ||
                    u.IndexOf("FromBase64",   StringComparison.Ordinal) >= 0))
                {
                    r.DotNetHasCryptoStub = true;
                }
            }
            catch
            {
                // Malformed metadata or unreadable PE — silently
                // skip. .NET reflection metadata is brittle on
                // obfuscated samples; we never want this to bring
                // down the parent scan.
            }
        }
    }

    // =================================================================
    // P10 — capability graph + verdict synthesis.
    // =================================================================

    public static class CapabilityGraph
    {
        /// <summary>
        /// Build (or rebuild) <see cref="AnalysisResult.Verdict"/>
        /// from the scored capabilities, applied floors, protection
        /// fingerprint and analysis status. Idempotent.
        /// </summary>
        public static void Build(AnalysisResult r)
        {
            if (r == null) return;
            var v = new FinalVerdict();

            // Verdict band — kept consistent with the existing
            // CLI / report bands (clean / low / medium / high /
            // critical) so consumers don't have to re-derive.
            int score = r.RiskScore;
            v.Verdict =
                score >= 90 ? "critical" :
                score >= 70 ? "high"     :
                score >= 50 ? "medium"   :
                score >= 25 ? "low"      :
                              "clean";
            // Confidence: clamp MaliciousConfidence into 0..100.
            v.Confidence = Math.Max(0, Math.Min(100, r.MaliciousConfidence));

            // Floors — copy in deterministic order, deduped.
            foreach (var f in r.AppliedFloors)
            {
                if (!v.Floors.Contains(f)) v.Floors.Add(f);
            }

            // Capabilities — pick CapabilityScores entries with
            // score >= 30 (publish threshold), sort descending.
            v.Capabilities = r.CapabilityScores
                .Where(kv => kv.Value >= 30 &&
                             !string.Equals(kv.Key, "AllowlistMatch",
                                            StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(kv => kv.Value)
                .Select(kv => kv.Key)
                .ToList();

            // Protection + analysis status mirror.
            if (r.Protection is not null)
                v.ProtectorGuess = r.Protection.ProtectorGuess;
            v.AnalysisStatus       = r.AnalysisStatus ?? "ok";
            v.RecommendedNextStage = r.RecommendedNextStage;

            // Reason: prefer the first applied floor (the strongest
            // structural evidence), then fall back to ReasonsShort.
            if (v.Floors.Count > 0)
                v.Reason = "floor:" + v.Floors[0];
            else if (!string.IsNullOrWhiteSpace(r.ReasonsShort))
                v.Reason = r.ReasonsShort;
            else if (v.Capabilities.Count > 0)
                v.Reason = "cap:" + v.Capabilities[0];
            else
                v.Reason = "no strong indicators";

            r.Verdict = v;
        }
    }
}
