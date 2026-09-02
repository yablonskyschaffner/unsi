// PR 15 — Section 4 — Stage L (Lua professional detect).
//
// Implements stages L1 ... L15 of the Lua hardening track:
//
//   L1  Lua fact engine — separate fact lists per concept.
//   L2  String deobfuscation: concat folding, string.char(...),
//       hex / decimal escapes, base64-in-Lua string, simple
//       byte-array XOR loops.
//   L3  Lua bytecode (\x1bLua) magic + string extraction.
//   L4  SA-MP / GTA Lua coverage.
//   L5  MoonLoader patterns (sampev.onSendDialogResponse,
//       lib.samp.events, inicfg, encoding.default).
//   L6  Lua HTTP / network sinks (socket.http, http.request,
//       ssl.https, asyncHttpRequest, ...).
//   L7  Lua file theft primitives + credential path chains
//       (io.open + AppData / Login Data / tdata / leveldb /
//       wallet.dat).
//   L8  Lua download+native-ext+load primitive chain (used by
//       Analyzer.Score() to apply a decisive floor of >=85).
//   L9  Lua credential-read + Telegram/Discord exfil chain
//       (used by Analyzer.Score() to apply a decisive floor of
//       >=90).
//   L10 ScriptIndicatorNeedles split by family — Lua-specific
//       needles are gated on FormatFamily == "Script-LUA" only.
//   L11 Tolerance: Lua tokens matched case-insensitively, but
//       Windows API names (LoadLibraryA, GetProcAddress, ...)
//       stay case-sensitive.
//   L12 Suspicious Lua requires (socket / ssl.https / lfs / ffi /
//       alien / winapi / effil / lanes) + ffi+LoadLibrary combo.
//   L13 Roblox / Luau branch (HttpGet, syn.request, setclipboard
//       + webhook combo).
//   L14 Lua comment FP protection — strip `--` line comments and
//       `--[[ ... ]]` block comments before generic indicator
//       scans, keep raw text for binary-payload detection.
//   L15 Context windows — only mark a chain as decisive when the
//       indicator strings are within an 8 KiB window of each
//       other.
//
// The detector is intentionally a single static class. It is
// invoked from the analyzer's non-PE classify path right after
// the existing DetectLuaThreats() call. Every fact is also fed
// back into the existing StringHits / ScriptIndicators lists so
// downstream score contributors (Score, B16 tiered facts) pick
// the signals up automatically.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace AntiStealerOneExe
{
    public sealed partial class AnalysisResult
    {
        // L1 — separate Lua fact lists. Populated by LuaDetectors.
        public List<string> LuaIndicators        { get; set; } = new();
        public List<string> LuaLoaderHits        { get; set; } = new();
        public List<string> LuaObfuscationHits   { get; set; } = new();
        public List<string> LuaSampHits          { get; set; } = new();
        public List<string> LuaExfilHits         { get; set; } = new();
        public List<string> LuaCredentialHits    { get; set; } = new();
        public List<string> LuaRequireHits       { get; set; } = new();
        public List<string> LuaRobloxHits        { get; set; } = new();
        // L8/L9 — chain markers that the analyzer's Score() consults.
        public bool LuaDownloadAndLoadChain      { get; set; }
        public bool LuaCredentialExfilChain      { get; set; }
        public bool LuaIsBytecode                { get; set; }
    }

    public static class LuaDetectors
    {
        // Hard limits to keep large blobs from blowing up the engine.
        private const int MaxDecodeIterations = 4;
        private const int MaxRescanBytes      = 4_000_000;
        private const int ContextWindowBytes  = 8 * 1024;

        // ----- L2 deobfuscation regexes ----------------------------------
        // "Load" .. "LibraryA" — string concat folding.
        private static readonly Regex ConcatFoldRegex = new(
            "\"([^\"\\n]{1,256})\"\\s*\\.\\.\\s*\"([^\"\\n]{1,256})\"",
            RegexOptions.Compiled, TimeSpan.FromSeconds(1));
        // string.char(76,111,...) -> "Lo..." (decimal byte sequence).
        private static readonly Regex StringCharRegex = new(
            @"string\.char\s*\(\s*([0-9]{1,3}(?:\s*,\s*[0-9]{1,3}){1,256})\s*\)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase,
            TimeSpan.FromSeconds(1));
        // table.concat({"a","b",...}) — folds the *literal* string members.
        private static readonly Regex TableConcatRegex = new(
            @"table\.concat\s*\(\s*\{\s*((?:""[^""\n]{0,80}""\s*,?\s*){2,64})\}",
            RegexOptions.Compiled | RegexOptions.IgnoreCase,
            TimeSpan.FromSeconds(1));
        private static readonly Regex TableMemberRegex = new(
            "\"([^\"\\n]{0,80})\"",
            RegexOptions.Compiled, TimeSpan.FromSeconds(1));
        // "\x41\x42" hex escapes inside a Lua string literal.
        private static readonly Regex HexEscapeRegex = new(
            @"\\x([0-9a-fA-F]{2})",
            RegexOptions.Compiled, TimeSpan.FromSeconds(1));
        // "\76\111" decimal escapes inside a Lua string literal.
        private static readonly Regex DecimalEscapeRegex = new(
            @"\\(\d{1,3})",
            RegexOptions.Compiled, TimeSpan.FromSeconds(1));
        // Base64 candidates ≥40 chars (smaller than the global blob regex
        // so a tight Lua-embedded URL still folds).
        private static readonly Regex LuaB64Regex = new(
            @"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})(?![A-Za-z0-9+/=])",
            RegexOptions.Compiled, TimeSpan.FromSeconds(1));

        // ----- L14 — comment stripping -----------------------------------
        // Strip --[[ ... ]] block comments first, then -- line comments.
        // Used only for *generic* indicator scans; the raw text is kept
        // separately so a binary-preserving signature scan still sees
        // payload bytes embedded inside what might look like a block
        // comment.
        private static readonly Regex BlockCommentRegex = new(
            @"--\[(=*)\[(?:.|\n)*?\]\1\]",
            RegexOptions.Compiled, TimeSpan.FromSeconds(1));
        private static readonly Regex LineCommentRegex = new(
            @"--[^\r\n]*",
            RegexOptions.Compiled, TimeSpan.FromSeconds(1));

        // ----- L10/L11 — Lua-only needles. Case-INSENSITIVE for Lua
        // tokens, but the Windows-API names stay case-sensitive below.
        private static readonly (string Needle, string Label)[] LuaPrimitives =
        {
            ("loadstring(",        "lua:loadstring"),
            ("load(",              "lua:load"),
            ("loadfile(",          "lua:loadfile"),
            ("dofile(",            "lua:dofile"),
            ("os.execute(",        "lua:os.execute"),
            ("io.popen(",          "lua:io.popen"),
            ("package.loadlib(",   "lua:package.loadlib"),
            ("require(",           "lua:require"),
            ("require ",           "lua:require"),
        };
        private static readonly (string Needle, string Label)[] LuaSampPrimitives =
        {
            // SA-MP / MoonLoader
            ("loadDynamicLibrary",         "lua:samp-loadlib"),
            ("requestHTTP(",               "lua:samp-http"),
            ("downloadUrlToFile(",         "lua:samp-download"),
            ("asyncHttpRequest",           "lua:moonloader-async-http"),
            ("sampRegisterChatCommand",    "lua:samp-chatcmd"),
            ("sampAddChatMessage",         "lua:samp-chatmsg"),
            ("sampSendChat",               "lua:samp-sendchat"),
            ("sampProcessChatInput",       "lua:samp-processchat"),
            ("sampGetPlayerNickname",      "lua:samp-nickname"),
            ("sampGetPlayerIdByCharHandle","lua:samp-id-by-char"),
            ("sampIsChatInputActive",      "lua:samp-chat-active"),
            ("sampIsDialogActive",         "lua:samp-dialog-active"),
            ("sampGetCurrentServerAddress","lua:samp-server-addr"),
            ("sampGetCurrentServerName",   "lua:samp-server-name"),
            ("sampGetCurrentServerPassword","lua:samp-server-pwd"),
            ("getServerAddress",           "lua:samp-server-addr"),
            ("getServerPassword",          "lua:samp-server-pwd"),
            ("getCurrentServerAddress",    "lua:samp-server-addr"),
            ("getCurrentServerName",       "lua:samp-server-name"),
            ("OnDialogResponse",           "lua:samp-on-dialog-response"),
            ("_sendCommand",               "lua:samp-sendcommand"),
            ("callFunction",               "lua:samp-callfunc"),
            // MoonLoader
            ("moonloader",                 "lua:moonloader"),
            ("lib.samp.events",            "lua:moonloader-events"),
            ("sampev.onSendDialogResponse","lua:moonloader-dlg-response"),
            ("sampev.onShowDialog",        "lua:moonloader-show-dialog"),
            ("samp.events",                "lua:moonloader-events"),
            ("inicfg",                     "lua:moonloader-inicfg"),
            ("encoding.default",           "lua:moonloader-encoding"),
        };
        private static readonly (string Needle, string Label)[] LuaHttpSinks =
        {
            ("socket.http",                "lua:net:socket-http"),
            ("http.request",               "lua:net:http-request"),
            ("ssl.https",                  "lua:net:ssl-https"),
            ("luasocket",                  "lua:net:luasocket"),
            ("copas.http",                 "lua:net:copas"),
            ("require(\"socket.http\")",   "lua:net:require-socket-http"),
            ("require 'socket.http'",      "lua:net:require-socket-http"),
            ("require \"socket.http\"",    "lua:net:require-socket-http"),
            ("require(\"ssl.https\")",     "lua:net:require-ssl-https"),
            ("require 'ssl.https'",        "lua:net:require-ssl-https"),
            ("effil.thread",               "lua:net:effil-thread"),
            ("requests.get(",              "lua:net:requests-get"),
            ("requests.post(",             "lua:net:requests-post"),
        };
        // Case-insensitive Lua file primitives.
        private static readonly string[] LuaFilePrimitives =
        {
            "io.open(", "io.lines(", "io.read(",
            "file:read", "file:write", "file:close",
            "lfs.dir(", "lfs.attributes(", "require(\"lfs\")",
            "os.getenv(\"APPDATA\")",
            "os.getenv(\"LOCALAPPDATA\")",
            "os.getenv('APPDATA')",
            "os.getenv('LOCALAPPDATA')",
        };
        // Credential paths Lua stealers typically open.
        private static readonly string[] LuaCredentialPaths =
        {
            @"\Google\Chrome\User Data",
            @"\Microsoft\Edge\User Data",
            @"\BraveSoftware\Brave-Browser",
            @"\Yandex\YandexBrowser",
            @"\Mozilla\Firefox\Profiles",
            "Login Data",
            "Cookies",
            "Web Data",
            "Local State",
            @"\Telegram Desktop\tdata",
            @"\discord\Local Storage\leveldb",
            @"\Discord\Local Storage\leveldb",
            "wallet.dat",
            @"\Exodus\exodus.wallet",
            @"\Electrum\wallets",
            @".aws\credentials",
            @".ssh\id_rsa",
        };
        // Suspicious requires.
        private static readonly string[] LuaSuspiciousRequires =
        {
            "require(\"socket\")",  "require 'socket'",  "require \"socket\"",
            "require(\"socket.http\")",
            "require(\"ssl.https\")", "require 'ssl.https'",
            "require(\"lfs\")", "require 'lfs'",
            "require(\"ffi\")", "require 'ffi'",
            "require(\"alien\")",
            "require(\"winapi\")", "require 'winapi'",
            "require(\"memory\")",
            "require(\"encoding\")",
            "require(\"effil\")",
            "require(\"lanes\")",
        };
        // Windows API names — kept case-sensitive (L11).
        private static readonly string[] WinApiCaseSensitiveTokens =
        {
            "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
            "VirtualAlloc", "VirtualProtect",
            "CryptUnprotectData", "WinHttpSendRequest",
            "InternetOpenA", "InternetOpenW",
        };
        // L13 — Roblox / Luau exploit script primitives.
        private static readonly (string Needle, string Label)[] RobloxPrimitives =
        {
            ("game:HttpGet",      "luau:game-httpget"),
            ("game:HttpGetAsync", "luau:game-httpget-async"),
            ("game:HttpPost",     "luau:game-httppost"),
            ("loadstring(game:HttpGet", "luau:loadstring-httpget"),
            ("syn.request",       "luau:syn-request"),
            ("http_request",      "luau:http-request"),
            ("request({",         "luau:request-table"),
            ("getgenv()",         "luau:getgenv"),
            ("setclipboard",      "luau:setclipboard"),
            ("identifyexecutor",  "luau:identifyexecutor"),
            ("hookfunction",      "luau:hookfunction"),
            ("getrawmetatable",   "luau:getrawmetatable"),
            ("setreadonly",       "luau:setreadonly"),
        };
        // L8 — download primitives.
        private static readonly string[] LuaDownloadPrimitives =
        {
            "downloadUrlToFile(", "requestHTTP(", "asyncHttpRequest",
            "socket.http", "http.request", "ssl.https",
            "game:HttpGet", "game:HttpGetAsync", "syn.request",
        };
        // L8 — native payload extensions.
        private static readonly string[] LuaNativePayloadExts =
        {
            ".asi", ".dll", ".exe", ".saa", ".bin", "update.bin",
        };
        // L8 — load / execute primitives.
        private static readonly string[] LuaLoadPrimitives =
        {
            "loadDynamicLibrary", "package.loadlib", "os.execute",
            "io.popen", "shellExecute", "ShellExecute",
        };
        // L9 — exfil sinks (Telegram / Discord patterns).
        private static readonly string[] LuaExfilSinks =
        {
            "api.telegram.org/bot",
            "/sendMessage", "/sendDocument", "/sendPhoto",
            "discord.com/api/webhooks",
            "discordapp.com/api/webhooks",
            "content=",
            "chat_id=",
            "parse_mode=",
        };

        // -----------------------------------------------------------------

        /// <summary>
        /// Run the full Lua detector pipeline. Safe to call multiple
        /// times (idempotent — duplicate hits are filtered).
        /// </summary>
        /// <param name="r">Analysis result to enrich.</param>
        /// <param name="rawBytes">Raw file bytes (binary-preserving).</param>
        public static void Run(AnalysisResult r, byte[] rawBytes)
        {
            if (r == null) return;
            bool gate = (r.FilePath != null &&
                         r.FilePath.EndsWith(".lua",  StringComparison.OrdinalIgnoreCase)) ||
                        (r.FilePath != null &&
                         r.FilePath.EndsWith(".luac", StringComparison.OrdinalIgnoreCase)) ||
                        string.Equals(r.FormatFamily, "Script-LUA",
                                      StringComparison.Ordinal) ||
                        string.Equals(r.FormatFamily, "Lua-Bytecode",
                                      StringComparison.Ordinal);
            if (!gate || rawBytes == null || rawBytes.Length == 0) return;

            // L3 — Lua bytecode magic. Detect first so subsequent stages
            // can decide whether comment stripping is meaningful.
            if (rawBytes.Length >= 4 &&
                rawBytes[0] == 0x1B && rawBytes[1] == (byte)'L' &&
                rawBytes[2] == (byte)'u' && rawBytes[3] == (byte)'a')
            {
                r.LuaIsBytecode  = true;
                r.FormatFamily   = "Lua-Bytecode";
                r.FileType       = "Lua bytecode";
                Add(r.LuaIndicators, "lua:bytecode");
            }

            // 1:1 byte->char so embedded payload bytes and the
            // signature scan are byte-exact. Capped to keep regex
            // engines happy on large blobs.
            int sliceLen = Math.Min(rawBytes.Length, MaxRescanBytes);
            var raw  = Encoding.Latin1.GetString(rawBytes, 0, sliceLen);

            // L14 — generic indicator scans run against the
            // comment-stripped form; the original `raw` is preserved
            // for binary-payload signature scans.
            var code = StripComments(raw);

            // L2 — iteratively unfold encoded strings until no more
            // changes (bounded by MaxDecodeIterations). Each pass:
            //   1. fold "A" .. "B"
            //   2. fold table.concat({"a","b",...})
            //   3. expand string.char(...)
            //   4. expand \xNN  and \DDD escapes
            //   5. base64-decode any candidate blobs
            var working = code;
            for (int i = 0; i < MaxDecodeIterations; i++)
            {
                var next = DecodeOnce(working, r);
                if (next == working) break;
                working = next;
            }
            // L2 — also rescan against the original (uncollapsed) text
            // so unusual escape sequences don't get swallowed.
            var deobf = working;

            // L10/L11 — apply Lua-specific needles (case-insensitive)
            // and Windows-API needles (case-sensitive).
            foreach (var (n, lbl) in LuaPrimitives)
                if (deobf.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    raw.IndexOf(n,   StringComparison.OrdinalIgnoreCase) >= 0)
                    Add(r.LuaIndicators, lbl);

            foreach (var (n, lbl) in LuaSampPrimitives)
                if (deobf.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    raw.IndexOf(n,   StringComparison.OrdinalIgnoreCase) >= 0)
                    Add(r.LuaSampHits, lbl);

            foreach (var (n, lbl) in LuaHttpSinks)
                if (deobf.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    raw.IndexOf(n,   StringComparison.OrdinalIgnoreCase) >= 0)
                    Add(r.LuaExfilHits, lbl);

            foreach (var fp in LuaFilePrimitives)
                if (deobf.IndexOf(fp, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    raw.IndexOf(fp,   StringComparison.OrdinalIgnoreCase) >= 0)
                    Add(r.LuaCredentialHits, "lua:file:" + fp.TrimEnd('('));

            foreach (var cp in LuaCredentialPaths)
                if (deobf.IndexOf(cp, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    raw.IndexOf(cp,   StringComparison.OrdinalIgnoreCase) >= 0)
                    Add(r.LuaCredentialHits, "lua:path:" + cp);

            foreach (var req in LuaSuspiciousRequires)
                if (deobf.IndexOf(req, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    raw.IndexOf(req,   StringComparison.OrdinalIgnoreCase) >= 0)
                    Add(r.LuaRequireHits, req);

            // Windows API names stay case-sensitive.
            foreach (var tok in WinApiCaseSensitiveTokens)
                if (deobf.IndexOf(tok, StringComparison.Ordinal) >= 0 ||
                    raw.IndexOf(tok,   StringComparison.Ordinal) >= 0)
                    Add(r.LuaLoaderHits, "lua:winapi:" + tok);

            foreach (var (n, lbl) in RobloxPrimitives)
                if (deobf.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    raw.IndexOf(n,   StringComparison.OrdinalIgnoreCase) >= 0)
                    Add(r.LuaRobloxHits, lbl);

            // L8/L9 — chain detection runs against the comment-stripped,
            // deobfuscated surface ONLY. Mentions inside line / block
            // comments must not be able to flip a behavioral chain
            // marker. The raw text is still used for binary signature
            // scans and for single-needle indicator collection above.
            //
            // The cred-exfil chain ALSO requires that the credential
            // path and the exfil sink occur within an 8 KiB context
            // window (L15), so a Lua file that mentions both far
            // apart (e.g. README + benign helper at the bottom)
            // doesn't fire the floor.
            r.LuaDownloadAndLoadChain =
                AnyOf(deobf, LuaDownloadPrimitives) &&
                AnyOf(deobf, LuaNativePayloadExts) &&
                AnyOf(deobf, LuaLoadPrimitives);
            if (r.LuaDownloadAndLoadChain)
                Add(r.LuaLoaderHits, "lua:chain:download-and-load");

            // Re-evaluate cred-read on the comment-stripped form so a
            // Lua file that *only* mentions Login Data in a comment
            // does not contribute to the chain.
            bool hasCredentialRead =
                AnyOf(deobf, new[] { "io.open(", "lfs.dir(", "io.lines(" }) &&
                AnyOf(deobf, LuaCredentialPaths);
            bool hasExfilSink = AnyOf(deobf, LuaExfilSinks);
            r.LuaCredentialExfilChain =
                hasCredentialRead && hasExfilSink &&
                WithinContextWindow(deobf, LuaCredentialPaths,
                                    LuaExfilSinks, ContextWindowBytes);
            if (r.LuaCredentialExfilChain)
                Add(r.LuaExfilHits, "lua:chain:cred-read-and-exfil");

            // ffi + LoadLibrary combo (L12).
            if (deobf.IndexOf("ffi.cdef", StringComparison.OrdinalIgnoreCase) >= 0 ||
                deobf.IndexOf("require(\"ffi\")", StringComparison.OrdinalIgnoreCase) >= 0 ||
                deobf.IndexOf("require 'ffi'",   StringComparison.OrdinalIgnoreCase) >= 0)
            {
                bool hasWinApi = WinApiCaseSensitiveTokens
                    .Any(t => deobf.IndexOf(t, StringComparison.Ordinal) >= 0);
                if (hasWinApi)
                    Add(r.LuaLoaderHits, "lua:chain:ffi-loadlibrary");
            }

            // Lua MoonLoader credential-dialog hook (L5).
            bool hasDialogHook =
                deobf.IndexOf("sampev.onSendDialogResponse",
                              StringComparison.OrdinalIgnoreCase) >= 0;
            bool hasPasswordCue =
                deobf.IndexOf("password", StringComparison.OrdinalIgnoreCase) >= 0 ||
                deobf.IndexOf("editbox",  StringComparison.OrdinalIgnoreCase) >= 0 ||
                deobf.IndexOf("pwd",      StringComparison.OrdinalIgnoreCase) >= 0;
            bool hasHttpExfilHook = AnyOf(deobf, LuaExfilSinks);
            if (hasDialogHook && hasPasswordCue && hasHttpExfilHook)
                Add(r.LuaSampHits, "lua:chain:samp-dialog-cred-exfil");

            // Roblox / Luau exploit script combo (L13).
            bool robloxClipboardCombo =
                r.LuaRobloxHits.Any(h => h.Equals("luau:setclipboard",
                                                  StringComparison.Ordinal)) &&
                AnyOf(deobf,
                    new[] { "token", "webhook", "discord.com/api/webhooks" });
            if (robloxClipboardCombo)
                Add(r.LuaRobloxHits, "luau:chain:setclipboard-token-webhook");

            // Mirror everything we found into the existing
            // ScriptIndicators / StringHits lists so the rest of the
            // analyzer (Score, B16 tiered facts) sees the signals.
            foreach (var ind in r.LuaIndicators
                                  .Concat(r.LuaLoaderHits)
                                  .Concat(r.LuaSampHits)
                                  .Concat(r.LuaExfilHits)
                                  .Concat(r.LuaCredentialHits)
                                  .Concat(r.LuaRequireHits)
                                  .Concat(r.LuaRobloxHits))
            {
                if (!r.ScriptIndicators.Contains(ind, StringComparer.Ordinal))
                    r.ScriptIndicators.Add(ind);
            }

            // L3 — bytecode string extraction.
            if (r.LuaIsBytecode)
                ExtractAsciiStrings(rawBytes, r);
        }

        // ----- L2 — single deobfuscation pass --------------------------
        private static string DecodeOnce(string src, AnalysisResult r)
        {
            var s = src;

            // 1. Concat folding
            try
            {
                var folded = ConcatFoldRegex.Replace(s, m =>
                    m.Groups[1].Value + m.Groups[2].Value);
                if (!ReferenceEquals(folded, s) && folded != s)
                {
                    s = folded;
                    Add(r.LuaObfuscationHits, "lua:deob:concat-fold");
                }
            }
            catch { }

            // 2. table.concat({"a","b",...}) folding
            try
            {
                var folded = TableConcatRegex.Replace(s, m =>
                {
                    var sb = new StringBuilder();
                    foreach (Match mm in TableMemberRegex.Matches(m.Groups[1].Value))
                        sb.Append(mm.Groups[1].Value);
                    return "\"" + sb + "\"";
                });
                if (folded != s)
                {
                    s = folded;
                    Add(r.LuaObfuscationHits, "lua:deob:table-concat");
                }
            }
            catch { }

            // 3. string.char(...) expansion
            try
            {
                var expanded = StringCharRegex.Replace(s, m =>
                {
                    var sb = new StringBuilder();
                    foreach (var tok in m.Groups[1].Value.Split(','))
                    {
                        if (int.TryParse(tok.Trim(), NumberStyles.Integer,
                                         CultureInfo.InvariantCulture, out var b)
                            && b >= 0 && b <= 255)
                            sb.Append((char)b);
                    }
                    return "\"" + sb + "\"";
                });
                if (expanded != s)
                {
                    s = expanded;
                    Add(r.LuaObfuscationHits, "lua:deob:string-char");
                }
            }
            catch { }

            // 4a. \xNN hex escapes
            try
            {
                var expanded = HexEscapeRegex.Replace(s, m =>
                    ((char)Convert.ToInt32(m.Groups[1].Value, 16)).ToString());
                if (expanded != s)
                {
                    s = expanded;
                    Add(r.LuaObfuscationHits, "lua:deob:hex-escape");
                }
            }
            catch { }

            // 4b. \DDD decimal escapes (only inside contexts that look
            //     like Lua strings — we settle for a global replace and
            //     accept some collateral on numeric literals; the
            //     downstream needles are exact-string so noise doesn't
            //     produce false matches).
            try
            {
                var expanded = DecimalEscapeRegex.Replace(s, m =>
                {
                    if (!int.TryParse(m.Groups[1].Value, NumberStyles.Integer,
                                      CultureInfo.InvariantCulture, out var b))
                        return m.Value;
                    if (b < 0 || b > 255) return m.Value;
                    return ((char)b).ToString();
                });
                if (expanded != s)
                {
                    s = expanded;
                    Add(r.LuaObfuscationHits, "lua:deob:decimal-escape");
                }
            }
            catch { }

            // 5. Base64-in-Lua decode (small candidates only).
            try
            {
                var b64 = LuaB64Regex.Replace(s, m =>
                {
                    var v = m.Value;
                    if (v.Length < 16 || v.Length > 4096) return v;
                    try
                    {
                        var bytes = Convert.FromBase64String(v);
                        if (bytes.Length < 8) return v;
                        var dec = Encoding.Latin1.GetString(bytes);
                        return v + " /*b64:*/ " + dec;
                    }
                    catch { return v; }
                });
                if (b64 != s)
                {
                    s = b64;
                    Add(r.LuaObfuscationHits, "lua:deob:base64");
                }
            }
            catch { }

            return s;
        }

        // ----- L14 — comment stripping ----------------------------------
        private static string StripComments(string src)
        {
            try
            {
                var s = BlockCommentRegex.Replace(src, " ");
                s = LineCommentRegex.Replace(s, " ");
                return s;
            }
            catch { return src; }
        }

        // ----- L15 — context window: are any pair of (a,b) needles
        // within `windowBytes` of each other in `src`?
        private static bool WithinContextWindow(
            string src,
            IReadOnlyList<string> aNeedles,
            IReadOnlyList<string> bNeedles,
            int windowBytes)
        {
            for (int i = 0; i < aNeedles.Count; i++)
            {
                var a = aNeedles[i];
                int ai = 0;
                while ((ai = src.IndexOf(a, ai,
                                         StringComparison.OrdinalIgnoreCase)) >= 0)
                {
                    for (int j = 0; j < bNeedles.Count; j++)
                    {
                        var b = bNeedles[j];
                        int bi = src.IndexOf(b,
                                             Math.Max(0, ai - windowBytes),
                                             StringComparison.OrdinalIgnoreCase);
                        if (bi >= 0 && Math.Abs(bi - ai) <= windowBytes)
                            return true;
                    }
                    ai += a.Length;
                }
            }
            return false;
        }

        private static bool AnyOf(string src, IReadOnlyCollection<string> needles)
        {
            foreach (var n in needles)
                if (src.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            return false;
        }

        private static void Add(List<string> list, string v)
        {
            if (list == null) return;
            if (list.Contains(v, StringComparer.Ordinal)) return;
            if (list.Count >= 128) return;
            list.Add(v);
        }

        // ----- L3 — bytecode string extraction. Looks for runs of >=6
        // ASCII printable characters and feeds them into StringHits
        // so the rest of the analyzer (URL scanner, credential path
        // matcher, etc.) sees what survived the bytecode compiler.
        private static void ExtractAsciiStrings(byte[] bytes, AnalysisResult r)
        {
            const int minRun = 6;
            int start = -1;
            int taken = 0;
            for (int i = 0; i < bytes.Length && taken < 64; i++)
            {
                byte b = bytes[i];
                bool printable = b >= 0x20 && b < 0x7F;
                if (printable)
                {
                    if (start < 0) start = i;
                }
                else
                {
                    if (start >= 0 && i - start >= minRun)
                    {
                        var s = Encoding.ASCII.GetString(bytes, start, i - start);
                        if (!r.StringHits.Contains(s, StringComparer.Ordinal))
                        {
                            r.StringHits.Add(s);
                            taken++;
                        }
                    }
                    start = -1;
                }
            }
        }
    }
}
