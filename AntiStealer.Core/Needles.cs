// Section 5.1 — Aho-Corasick wrappers around the analyser's static
// needle lists. The hot path used to do `foreach (var n in needles)
// haystack.IndexOf(n)`, which is O(N·K). With Aho-Corasick we walk the
// haystack once (O(N)) and recover every match in a single pass.
//
// All instances are lazy-initialised (Section 5.7 — defer until the
// first scan touches them) so that a CLI invocation that never reaches
// the analyser (e.g. `--version`, `license verify`) doesn't pay the
// trie-build cost.
//
// The trie itself lives in Perf.cs (Section FF2). This file only owns
// the curated lists of needles + a couple of convenience helpers.
using System;
using System.Collections.Generic;
using System.Linq;

namespace AntiStealerOneExe
{
    /// <summary>
    /// Pre-built Aho-Corasick tries over the analyser's static needle
    /// lists. All matchers are case-insensitive (the haystacks are
    /// lower-cased before traversal so the input case doesn't matter).
    /// </summary>
    public static class Needles
    {
        // ---------- Suspicious string needles -----------------------------
        // Every string here is lower-case so we can compare with a single
        // ToLowerInvariant pass on the haystack. The list mirrors
        // Analyzer.SuspiciousStringNeedles (the original is kept in
        // Analyzer.cs as the documented source-of-truth; this is the
        // matcher built from it).
        public static readonly string[] SuspiciousStringList =
        {
            "password", "login data", "cookies", "cookie", "token", "authorization", "refresh_token", "master_key",
            "local state", "web data", "chrome", "chromium", "edge", "opera", "firefox", "brave", "yandex",
            "telegram", "api.telegram.org", "t.me/", "discord", "webhook", "discordapp.com/api/webhooks",
            "steam", "wallet", "seed", "metamask", "exodus", "phantom", "atomicwallet",
            "cryptunprotectdata", "dpapi", "aes", "sqlite", "vault", "wallet.dat",
            "appdata", "localappdata", "\\users\\", "\\profiles\\",
            "startup", "run\\", "taskschd", "schtasks", "autorun", "clipper", "grabber", "stealer"
        };

        public static readonly Lazy<AhoCorasick> SuspiciousStringAc =
            new(() => new AhoCorasick(SuspiciousStringList, ignoreCase: true));

        // ---------- Suspicious API needles --------------------------------
        // Mirrors Analyzer.SuspiciousApiNeedles. We feed the haystack
        // (concatenation of imports) lower-cased; the AC instance is
        // case-insensitive.
        public static readonly string[] SuspiciousApiList =
        {
            "CryptUnprotectData", "BCryptDecrypt", "InternetOpen", "InternetOpenUrl", "InternetReadFile", "WinHttpOpen",
            "WinHttpConnect", "WinHttpSendRequest", "HttpSendRequest", "URLDownloadToFile", "socket", "connect", "send", "recv",
            "WSAStartup", "DnsQuery", "CreateToolhelp32Snapshot", "RegOpenKey", "RegSetValue", "OpenProcess",
            "ReadProcessMemory", "WriteProcessMemory", "VirtualAllocEx", "CreateRemoteThread", "MiniDumpWriteDump",
            "SetWindowsHookEx", "GetAsyncKeyState", "NtQueryInformationProcess", "IsDebuggerPresent",
            "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext", "ResumeThread", "CreateFileW", "RegCreateKeyEx",
            "WinVerifyTrust", "BCryptGenRandom", "CryptAcquireContext", "CryptDecrypt", "GetAdaptersAddresses"
        };

        public static readonly Lazy<AhoCorasick> SuspiciousApiAc =
            new(() => new AhoCorasick(SuspiciousApiList, ignoreCase: true));

        /// <summary>
        /// Returns the subset of <see cref="SuspiciousApiList"/> that appear
        /// (case-insensitively) anywhere in the concatenation of the supplied
        /// import names. Replaces the previous O(N·K)
        /// <c>foreach api { imports.Any(...) }</c> loop with a single AC pass.
        /// </summary>
        public static List<string> MatchSuspiciousApis(IEnumerable<string> imports)
        {
            // Build one big lower-case haystack with separators so a needle
            // can't accidentally span two import names.
            var sb = new System.Text.StringBuilder(4096);
            foreach (var i in imports)
            {
                if (string.IsNullOrEmpty(i)) continue;
                sb.Append(i.ToLowerInvariant()).Append('\u0001');
            }
            var matched = SuspiciousApiAc.Value.FindUniquePatterns(sb.ToString());

            // AhoCorasick stores the original (pre-`ToLowerInvariant`)
            // pattern in its Outputs list, so the matched set already has
            // the canonical casing we want to surface — just preserve the
            // declaration order of `SuspiciousApiList` for stable reports.
            var canonical = new List<string>(matched.Count);
            foreach (var api in SuspiciousApiList)
                if (matched.Contains(api)) canonical.Add(api);
            return canonical;
        }
    }
}
