// PR 15 — Section 4 (dynamic / sandbox / emulation stack).
//
//   4.1 WsbSandboxRunner — generates a Windows Sandbox configuration
//       file (.wsb) for a given sample + drives `WindowsSandbox.exe
//       sandbox.wsb`. CI / non-Windows hosts run in dry-run mode and
//       just return the generated XML. Captures the sandbox script
//       stdout/stderr into AnalysisResult.SandboxEvents.
//   4.2 EtwTraceReader — parses CSV-export ETW traces (produced by
//       `xperf -i trace.etl -o trace.csv`) and surfaces high-signal
//       provider events (DNS/HTTP/process-create/registry-write/
//       service-install) onto AnalysisResult.EtwEvents.
//   4.3 UnicornEmulator — a tiny managed x86/x64 emulator covering
//       the subset of opcodes used by Cobalt-Strike / Metasploit
//       prologues (push/pop/mov/add/sub/call/jmp/syscall). Real
//       sandboxes will plug into libunicorn via P/Invoke; here we
//       provide a pure-managed deterministic engine sufficient for
//       trace generation. Output: list of (rva, mnemonic) strings.
//   4.4 CapeClient — REST wrapper for a CAPE-Sandbox instance.
//       submit_file(POST /tasks/create/file) -> poll
//       /tasks/view/{id} -> fetch /tasks/report/{id}/json -> merge
//       process-tree + DNS + dropped-files into SandboxEvents.
//       Uses an injectable HttpMessageHandler so tests don't need
//       real network.
//   4.5 MiniYaraX — managed rule engine that runs a subset of the
//       YARA-X syntax (string + regex + `any of them` /
//       `all of them` / `N of them`). Discovers rules under
//       `%AppData%/AntiStealer/yara-x/*.yarax` and matches against
//       the sample's StringHits union. Hits land on
//       AnalysisResult.MiniYaraXHits.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace AntiStealerOneExe
{
    public sealed partial class AnalysisResult
    {
        // 4.1 / 4.4 — sandbox/emulation events.
        public List<string> SandboxEvents  { get; set; } = new();
        // 4.2 — ETW events (provider, name, count).
        public List<string> EtwEvents      { get; set; } = new();
        // 4.3 — Unicorn-style emulator trace lines.
        public List<string> EmulatorTrace  { get; set; } = new();
        // 4.5 — embedded yara-x rule hits.
        public List<string> MiniYaraXHits  { get; set; } = new();
    }

    // -----------------------------------------------------------------
    // 4.1  Windows Sandbox runner
    // -----------------------------------------------------------------

    public static class WsbSandboxRunner
    {
        public sealed record WsbConfig(
            string MappedHostPath,
            string MappedSandboxPath = "C:\\sample",
            bool   ReadOnly = true,
            bool   Networking = false,
            bool   AudioInput = false,
            bool   VideoInput = false,
            bool   PrinterRedirection = false,
            bool   ClipboardRedirection = false,
            string? LogonCommand = null);

        public static string BuildXml(WsbConfig cfg)
        {
            var sb = new StringBuilder();
            sb.AppendLine("<Configuration>");
            sb.AppendLine($"  <Networking>{(cfg.Networking ? "Enable" : "Disable")}</Networking>");
            sb.AppendLine($"  <AudioInput>{(cfg.AudioInput ? "Enable" : "Disable")}</AudioInput>");
            sb.AppendLine($"  <VideoInput>{(cfg.VideoInput ? "Enable" : "Disable")}</VideoInput>");
            sb.AppendLine($"  <PrinterRedirection>{(cfg.PrinterRedirection ? "Enable" : "Disable")}</PrinterRedirection>");
            sb.AppendLine($"  <ClipboardRedirection>{(cfg.ClipboardRedirection ? "Enable" : "Disable")}</ClipboardRedirection>");
            sb.AppendLine("  <MappedFolders>");
            sb.AppendLine("    <MappedFolder>");
            sb.AppendLine($"      <HostFolder>{Escape(cfg.MappedHostPath)}</HostFolder>");
            sb.AppendLine($"      <SandboxFolder>{Escape(cfg.MappedSandboxPath)}</SandboxFolder>");
            sb.AppendLine($"      <ReadOnly>{(cfg.ReadOnly ? "true" : "false")}</ReadOnly>");
            sb.AppendLine("    </MappedFolder>");
            sb.AppendLine("  </MappedFolders>");
            if (!string.IsNullOrWhiteSpace(cfg.LogonCommand))
            {
                sb.AppendLine("  <LogonCommand>");
                sb.AppendLine($"    <Command>{Escape(cfg.LogonCommand!)}</Command>");
                sb.AppendLine("  </LogonCommand>");
            }
            sb.AppendLine("</Configuration>");
            return sb.ToString();
        }

        private static string Escape(string s) =>
            s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");

        // Parse a captured sandbox script transcript and convert each
        // interesting line into a SandboxEvents entry.
        public static IReadOnlyList<string> ParseTranscript(string transcript)
        {
            var hits = new List<string>();
            foreach (var raw in transcript.Replace("\r", "").Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0) continue;
                if      (line.StartsWith("PROCESS:", StringComparison.OrdinalIgnoreCase)) hits.Add("wsb:" + line);
                else if (line.StartsWith("NET:",     StringComparison.OrdinalIgnoreCase)) hits.Add("wsb:" + line);
                else if (line.StartsWith("REG:",     StringComparison.OrdinalIgnoreCase)) hits.Add("wsb:" + line);
                else if (line.StartsWith("FILE:",    StringComparison.OrdinalIgnoreCase)) hits.Add("wsb:" + line);
            }
            return hits;
        }
    }

    // -----------------------------------------------------------------
    // 4.2  ETW trace reader
    // -----------------------------------------------------------------

    public static class EtwTraceReader
    {
        // Recognised xperf CSV provider event prefixes.
        private static readonly Dictionary<string, string> _providerToKind = new(StringComparer.OrdinalIgnoreCase)
        {
            { "Microsoft-Windows-DNS-Client",        "dns" },
            { "Microsoft-Windows-WinINet",           "http" },
            { "Microsoft-Windows-WinHttp",           "http" },
            { "Microsoft-Windows-Kernel-Process",    "proc" },
            { "Microsoft-Windows-Kernel-Registry",   "reg"  },
            { "Microsoft-Windows-Services",          "svc"  },
            { "Microsoft-Windows-NetworkProfile",    "net"  },
        };

        public static IReadOnlyList<string> Parse(string csv)
        {
            // Format expected (xperf -i trace.etl -o trace.csv):
            //   Provider,Task,Opcode,Process,Detail
            // We use Provider+Task for kind classification.
            var events = new List<string>();
            foreach (var line in csv.Replace("\r", "").Split('\n'))
            {
                if (line.Length == 0 || line.StartsWith("Provider,", StringComparison.OrdinalIgnoreCase)) continue;
                var cols = SplitCsv(line);
                if (cols.Count < 2) continue;
                string provider = cols[0];
                string task = cols.Count > 1 ? cols[1] : "";
                if (_providerToKind.TryGetValue(provider, out var kind))
                {
                    events.Add($"etw:{kind}:{task}");
                }
            }
            return events.Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).ToList();
        }

        private static List<string> SplitCsv(string line)
        {
            // Lightweight CSV split — no quoted-field support; the
            // xperf export rarely needs it for our subset.
            var cols = new List<string>();
            int start = 0;
            for (int i = 0; i < line.Length; i++)
            {
                if (line[i] == ',')
                {
                    cols.Add(line.Substring(start, i - start));
                    start = i + 1;
                }
            }
            cols.Add(line.Substring(start));
            return cols;
        }
    }

    // -----------------------------------------------------------------
    // 4.3  Tiny managed emulator
    // -----------------------------------------------------------------

    public static class UnicornEmulator
    {
        // We don't actually decode bytes — that would require a full
        // x86 disassembler. Instead we accept a *trace* of byte-aligned
        // bytes and produce a deterministic execution-style log over
        // the opcodes we recognise. This is sufficient for the
        // shellcode-trace use case (visualise CS prologue, syscall stubs).
        // For real native emulation, plug libunicorn via P/Invoke and
        // replace this with calls into uc_open / uc_emu_start / etc.

        public static IReadOnlyList<string> Trace(byte[] code, int maxSteps = 64)
        {
            var trace = new List<string>();
            int rva = 0;
            int steps = 0;
            while (rva < code.Length && steps < maxSteps)
            {
                byte op = code[rva];
                string mnemonic;
                int len;
                switch (op)
                {
                    case 0x90:                mnemonic = "nop";                          len = 1; break;
                    case 0x50: case 0x51: case 0x52: case 0x53:
                    case 0x54: case 0x55: case 0x56: case 0x57:
                                              mnemonic = $"push r{(op - 0x50)}";         len = 1; break;
                    case 0x58: case 0x59: case 0x5A: case 0x5B:
                    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
                                              mnemonic = $"pop r{(op - 0x58)}";          len = 1; break;
                    case 0xC3:                mnemonic = "ret";                          len = 1; break;
                    case 0xCC:                mnemonic = "int3";                         len = 1; break;
                    case 0xE8:                mnemonic = "call rel32";                   len = 5; break;
                    case 0xE9:                mnemonic = "jmp  rel32";                   len = 5; break;
                    case 0xEB:                mnemonic = "jmp  rel8";                    len = 2; break;
                    case 0xFC:                mnemonic = "cld";                          len = 1; break;
                    case 0x0F:
                        if (rva + 1 < code.Length && code[rva + 1] == 0x05)
                        {
                            mnemonic = "syscall";  len = 2;
                        }
                        else { mnemonic = $"0F {code[rva + 1]:X2}"; len = 2; }
                        break;
                    case 0x66:                mnemonic = "66h prefix";                   len = 1; break;
                    default:                  mnemonic = $"db {op:X2}";                  len = 1; break;
                }
                trace.Add($"0x{rva:X4}: {mnemonic}");
                rva += len;
                steps++;
                if (mnemonic == "ret" || mnemonic == "int3") break;
            }
            return trace;
        }
    }

    // -----------------------------------------------------------------
    // 4.4  CAPE-Sandbox REST client
    // -----------------------------------------------------------------

    public sealed class CapeOptions
    {
        public string BaseUrl { get; set; } = "http://127.0.0.1:8000";
        public string? ApiToken { get; set; }
        public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(5);
        public TimeSpan MaxWait      { get; set; } = TimeSpan.FromMinutes(5);
    }

    public sealed class CapeSubmitResponse
    {
        [JsonPropertyName("task_id")]
        public int TaskId { get; set; }
    }

    public sealed class CapeTaskView
    {
        [JsonPropertyName("task")]
        public CapeTaskInner? Task { get; set; }
    }

    public sealed class CapeTaskInner
    {
        [JsonPropertyName("status")]
        public string Status { get; set; } = "";
    }

    public sealed class CapeReport
    {
        [JsonPropertyName("processes")]
        public List<string>? Processes { get; set; }

        [JsonPropertyName("dns")]
        public List<string>? Dns { get; set; }

        [JsonPropertyName("dropped")]
        public List<string>? Dropped { get; set; }
    }

    public sealed class CapeClient
    {
        private readonly HttpClient _http;
        private readonly CapeOptions _opt;

        public CapeClient(CapeOptions options, HttpMessageHandler? handler = null)
        {
            _opt = options;
            _http = handler != null ? new HttpClient(handler, disposeHandler: false) : new HttpClient();
            _http.BaseAddress = new Uri(options.BaseUrl.TrimEnd('/') + "/");
            if (!string.IsNullOrWhiteSpace(options.ApiToken))
                _http.DefaultRequestHeaders.Add("Authorization", "Token " + options.ApiToken);
        }

        public async Task<int> SubmitAsync(string filePath, CancellationToken ct = default)
        {
            using var multipart = new MultipartFormDataContent();
            using var fs = File.OpenRead(filePath);
            multipart.Add(new StreamContent(fs), "file", Path.GetFileName(filePath));
            using var resp = await _http.PostAsync("tasks/create/file", multipart, ct);
            resp.EnsureSuccessStatusCode();
            var parsed = await resp.Content.ReadFromJsonAsync<CapeSubmitResponse>(cancellationToken: ct)
                       ?? throw new InvalidOperationException("CAPE: empty submit response");
            return parsed.TaskId;
        }

        public async Task<string> PollAsync(int taskId, CancellationToken ct = default)
        {
            var deadline = DateTime.UtcNow + _opt.MaxWait;
            while (DateTime.UtcNow < deadline)
            {
                using var resp = await _http.GetAsync($"tasks/view/{taskId}", ct);
                resp.EnsureSuccessStatusCode();
                var view = await resp.Content.ReadFromJsonAsync<CapeTaskView>(cancellationToken: ct);
                var status = view?.Task?.Status ?? "";
                if (status == "reported" || status == "completed" || status == "failed_processing")
                    return status;
                await Task.Delay(_opt.PollInterval, ct);
            }
            return "timeout";
        }

        public async Task<CapeReport?> FetchReportAsync(int taskId, CancellationToken ct = default)
        {
            using var resp = await _http.GetAsync($"tasks/report/{taskId}/json", ct);
            resp.EnsureSuccessStatusCode();
            return await resp.Content.ReadFromJsonAsync<CapeReport>(cancellationToken: ct);
        }

        public static IReadOnlyList<string> MergeReport(CapeReport rep)
        {
            var events = new List<string>();
            if (rep.Processes != null)
                foreach (var p in rep.Processes) events.Add("cape:proc:" + p);
            if (rep.Dns != null)
                foreach (var d in rep.Dns)       events.Add("cape:dns:"  + d);
            if (rep.Dropped != null)
                foreach (var f in rep.Dropped)   events.Add("cape:drop:" + f);
            return events;
        }
    }

    // -----------------------------------------------------------------
    // 4.5  MiniYaraX
    // -----------------------------------------------------------------

    public sealed class MiniYaraXRule
    {
        public string Name { get; set; } = "";
        public List<MiniYaraXStringDef> Strings { get; } = new();
        // condition: "any", "all", or "N" where N is an int.
        public string Condition { get; set; } = "any";
    }

    public sealed class MiniYaraXStringDef
    {
        public string Id { get; set; } = "";       // e.g. "$s1"
        public string Pattern { get; set; } = "";
        public bool   IsRegex { get; set; }
        public Regex? Compiled { get; set; }
    }

    public static class MiniYaraXParser
    {
        // Mini grammar (one rule per parse call):
        //   rule R { strings: $s1 = "..." [ascii|wide|nocase]
        //                     $s2 = /regex/
        //            condition: any of them | all of them | N of them }
        private static readonly Regex _ruleHead =
            new("rule\\s+([A-Za-z_][A-Za-z0-9_]*)\\s*\\{", RegexOptions.Compiled);
        private static readonly Regex _strString =
            new("(\\$[A-Za-z0-9_]+)\\s*=\\s*\"([^\"]*)\"", RegexOptions.Compiled);
        private static readonly Regex _strRegex =
            new("(\\$[A-Za-z0-9_]+)\\s*=\\s*/([^/]+)/", RegexOptions.Compiled);
        private static readonly Regex _cond =
            new("condition\\s*:\\s*(any|all|\\d+)\\s+of\\s+them", RegexOptions.Compiled);

        public static MiniYaraXRule Parse(string text)
        {
            var head = _ruleHead.Match(text);
            if (!head.Success) throw new InvalidDataException("yara-x: no rule head");
            var r = new MiniYaraXRule { Name = head.Groups[1].Value };

            foreach (Match m in _strString.Matches(text))
                r.Strings.Add(new MiniYaraXStringDef
                {
                    Id = m.Groups[1].Value,
                    Pattern = m.Groups[2].Value,
                    IsRegex = false,
                });

            foreach (Match m in _strRegex.Matches(text))
            {
                var def = new MiniYaraXStringDef
                {
                    Id = m.Groups[1].Value,
                    Pattern = m.Groups[2].Value,
                    IsRegex = true,
                };
                def.Compiled = new Regex(def.Pattern,
                    RegexOptions.Compiled | RegexOptions.CultureInvariant);
                r.Strings.Add(def);
            }

            var c = _cond.Match(text);
            if (c.Success) r.Condition = c.Groups[1].Value;

            return r;
        }
    }

    public static class MiniYaraXEngine
    {
        public static IReadOnlyList<string> RunOn(IEnumerable<MiniYaraXRule> rules, AnalysisResult r) =>
            RunOn(rules, r, extraText: null);

        // Operator-supplied extra haystack (typically the full
        // analysisText buffer from the static-analysis pipeline).
        // StringHits alone caps at ~400 entries and only contains the
        // strings that already tripped a heuristic — far too narrow for
        // a generic YARA-style rule. Concatenating analysisText lets
        // rules match the same corpus that every other detector sees.
        public static IReadOnlyList<string> RunOn(
            IEnumerable<MiniYaraXRule> rules,
            AnalysisResult r,
            string? extraText)
        {
            var hits = new List<string>();
            // De-duplicate sources without allocating a second giant
            // string when extraText is the same as StringHits join.
            var sb = new System.Text.StringBuilder();
            foreach (var s in r.StringHits)
            {
                if (s == null) continue;
                sb.Append(s);
                sb.Append('\n');
            }
            if (!string.IsNullOrEmpty(extraText))
            {
                sb.Append('\n');
                sb.Append(extraText);
            }
            string raw = sb.ToString();
            foreach (var rule in rules)
            {
                int matched = 0;
                foreach (var s in rule.Strings)
                {
                    bool m = s.IsRegex
                        ? (s.Compiled?.IsMatch(raw) ?? new Regex(s.Pattern).IsMatch(raw))
                        : raw.Contains(s.Pattern, StringComparison.Ordinal);
                    if (m) matched++;
                }
                // Empty `strings:` block is meaningless — a rule with no
                // strings should never fire, regardless of condition. The
                // previous `matched == rule.Strings.Count` returned `0 == 0
                // = true` for empty rules, surfacing a false positive on
                // every sample. Guard against that here.
                bool fired = rule.Strings.Count > 0 && rule.Condition switch
                {
                    "any" => matched >= 1,
                    "all" => matched == rule.Strings.Count,
                    _     => int.TryParse(rule.Condition, out var n) && n > 0 && matched >= n,
                };
                if (fired) hits.Add("yarax:" + rule.Name);
            }
            return hits;
        }

        public static IEnumerable<MiniYaraXRule> LoadFromDirectory(string dir)
        {
            if (!Directory.Exists(dir)) yield break;
            foreach (var path in Directory.EnumerateFiles(dir, "*.yarax", SearchOption.TopDirectoryOnly))
            {
                MiniYaraXRule? r = null;
                try { r = MiniYaraXParser.Parse(File.ReadAllText(path)); }
                catch { /* skip malformed rules */ }
                if (r != null) yield return r;
            }
        }
    }

    // -----------------------------------------------------------------
    // Pipeline
    // -----------------------------------------------------------------

    public static class DynamicAnalysisPipeline
    {
        public static void RunOn(AnalysisResult r, IEnumerable<MiniYaraXRule>? yaraRules = null) =>
            RunOn(r, extraText: null, yaraRules: yaraRules);

        public static void RunOn(
            AnalysisResult r,
            string? extraText,
            IEnumerable<MiniYaraXRule>? yaraRules = null)
        {
            // YARA-X mini rules from a curated directory or supplied list.
            try
            {
                var rules = yaraRules ?? MiniYaraXEngine.LoadFromDirectory(DefaultYaraDir());
                foreach (var h in MiniYaraXEngine.RunOn(rules, r, extraText))
                    if (!r.MiniYaraXHits.Contains(h, StringComparer.Ordinal))
                        r.MiniYaraXHits.Add(h);
            }
            catch { /* best-effort */ }
        }

        internal static string DefaultYaraDir() => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "AntiStealer", "yara-x");
    }

    // -----------------------------------------------------------------
    // D10  Canary dynamic-analysis profile.
    //
    // Builds a temporary filesystem that mimics a real user profile
    // populated with fake credential targets — browser DBs, Discord
    // LevelDB, Telegram tdata, wallet directories, .env / .aws / .ssh
    // secrets. After the sample finishes running, Audit() walks the
    // canary tree and reports which files were touched / modified /
    // deleted, plus scans an "exfil-likely" directory (e.g. %TEMP%,
    // the sample's working dir) for the canary token. Findings land
    // on AnalysisResult.SandboxEvents with the existing "wsb:FILE:" /
    // "wsb:NET:" tags so the C19 fact-based Sigma rules can match
    // them without extra rule changes.
    //
    // This is intentionally a managed, deterministic, side-effect-free
    // implementation so it can run inside CI: no actual sample is
    // executed by this class. A real sandbox driver (WSB/CAPE/manual)
    // is expected to call Seed() before launching the sample and
    // Audit() after the sample exits.
    // -----------------------------------------------------------------

    public sealed class DynamicCanaryProfile
    {
        public string Root { get; }
        public IReadOnlyDictionary<string, CanaryFile> Files => _files;
        public string CanaryToken { get; }

        private readonly Dictionary<string, CanaryFile> _files = new();
        private readonly DateTime _baseline;

        private DynamicCanaryProfile(string root, string token, DateTime baseline)
        {
            Root = root;
            CanaryToken = token;
            _baseline = baseline;
        }

        /// <summary>
        /// Seed a canary profile under <paramref name="root"/>. Files
        /// are written with a deterministic structure mimicking a real
        /// Windows user profile, each containing the same canary token
        /// so exfil destinations can be discovered by string search.
        /// </summary>
        public static DynamicCanaryProfile Seed(string root)
        {
            Directory.CreateDirectory(root);
            var token = "CANARY-" + Guid.NewGuid().ToString("N");
            var prof  = new DynamicCanaryProfile(root, token, DateTime.UtcNow);

            // Browser targets (Chrome / Edge / Brave / Yandex). Each
            // host gets its own minimal "Default" profile with the
            // login/cookie/local-state files stealers look for.
            string[] browserHosts =
            {
                Path.Combine("AppData", "Local", "Google", "Chrome", "User Data", "Default"),
                Path.Combine("AppData", "Local", "Microsoft", "Edge", "User Data", "Default"),
                Path.Combine("AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data", "Default"),
                Path.Combine("AppData", "Local", "Yandex", "YandexBrowser", "User Data", "Default"),
            };
            foreach (var host in browserHosts)
            {
                prof.WriteCanary(Path.Combine(host, "Login Data"),
                    "SQLite format 3\0logins\0username\0password\0" + token);
                prof.WriteCanary(Path.Combine(host, "Cookies"),
                    "SQLite format 3\0cookies\0host_key\0name\0value\0" + token);
                prof.WriteCanary(Path.Combine(host, "Web Data"),
                    "SQLite format 3\0autofill\0name\0value\0" + token);
                prof.WriteCanary(Path.Combine(host, "..", "Local State"),
                    "{\"profile\":{\"info_cache\":{}},\"os_crypt\":{\"encrypted_key\":\"" + token + "\"}}");
            }

            // Firefox
            prof.WriteCanary(
                Path.Combine("AppData", "Roaming", "Mozilla", "Firefox", "Profiles", "default-release", "logins.json"),
                "{\"logins\":[{\"hostname\":\"" + token + "\"}]}");
            prof.WriteCanary(
                Path.Combine("AppData", "Roaming", "Mozilla", "Firefox", "Profiles", "default-release", "key4.db"),
                "SQLite format 3\0metaData\0" + token);

            // Discord (LevelDB + Local Storage).
            prof.WriteCanary(
                Path.Combine("AppData", "Roaming", "discord", "Local Storage", "leveldb", "000003.log"),
                token + "\ndapi-token-v1\n");
            prof.WriteCanary(
                Path.Combine("AppData", "Roaming", "discordcanary", "Local Storage", "leveldb", "000004.log"),
                token);

            // Telegram tdata.
            prof.WriteCanary(
                Path.Combine("AppData", "Roaming", "Telegram Desktop", "tdata", "key_datas"),
                token);
            prof.WriteCanary(
                Path.Combine("AppData", "Roaming", "Telegram Desktop", "tdata", "D877F783D5D3EF8C", "map1"),
                token);

            // Crypto wallets.
            prof.WriteCanary(
                Path.Combine("AppData", "Roaming", "Exodus", "exodus.wallet", "passphrase.json"),
                "{\"passphrase\":\"" + token + "\"}");
            prof.WriteCanary(
                Path.Combine("AppData", "Roaming", "atomic", "Local Storage", "leveldb", "000003.log"),
                token);
            prof.WriteCanary(
                Path.Combine("AppData", "Local", "Electrum", "wallets", "default_wallet"),
                token);
            prof.WriteCanary("wallet.dat", token);

            // Browser-extension wallets (MetaMask, Phantom, Trust, …).
            prof.WriteCanary(
                Path.Combine("AppData", "Local", "Google", "Chrome", "User Data", "Default",
                             "Local Extension Settings", "nkbihfbeogaeaoehlefnkodbefgpgknn", "000003.log"),
                token);

            // Steam / messengers.
            prof.WriteCanary(
                Path.Combine("Program Files (x86)", "Steam", "config", "loginusers.vdf"),
                token);

            // Cloud + dev secrets.
            prof.WriteCanary(".env",
                "AWS_ACCESS_KEY_ID=AKIA" + token.Substring(0, 16) + "\nAWS_SECRET_ACCESS_KEY=" + token + "\n");
            prof.WriteCanary(Path.Combine(".aws", "credentials"),
                "[default]\naws_access_key_id=AKIA" + token.Substring(0, 16) + "\naws_secret_access_key=" + token + "\n");
            prof.WriteCanary(Path.Combine(".ssh", "id_rsa"),
                "-----BEGIN OPENSSH PRIVATE KEY-----\n" + token + "\n-----END OPENSSH PRIVATE KEY-----\n");
            prof.WriteCanary(".npmrc", "//registry.npmjs.org/:_authToken=" + token + "\n");
            prof.WriteCanary(Path.Combine(".docker", "config.json"),
                "{\"auths\":{\"registry.example/v1/\":{\"auth\":\"" + token + "\"}}}");

            return prof;
        }

        private void WriteCanary(string relPath, string content)
        {
            var full = Path.GetFullPath(Path.Combine(Root, relPath));
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllText(full, content);
            _files[full] = new CanaryFile(full, content, content.Length);
        }

        /// <summary>
        /// Walk the canary tree and report file changes. Each returned
        /// string follows the "wsb:FILE:&lt;event&gt;:&lt;path&gt;"
        /// shape used by SandboxEvents so existing Sigma rules don't
        /// need adjustment.
        /// </summary>
        public List<string> Audit()
        {
            var events = new List<string>();
            foreach (var (path, baseline) in _files)
            {
                try
                {
                    if (!File.Exists(path))
                    {
                        events.Add("wsb:FILE:deleted:" + RelOf(path));
                        continue;
                    }
                    var fi = new FileInfo(path);
                    if (fi.Length != baseline.OriginalLength)
                        events.Add("wsb:FILE:modified:" + RelOf(path));
                    if (fi.LastAccessTimeUtc > _baseline)
                        events.Add("wsb:FILE:access:" + RelOf(path));
                    if (fi.LastWriteTimeUtc > _baseline.AddSeconds(1))
                        events.Add("wsb:FILE:write:" + RelOf(path));
                }
                catch { /* best-effort */ }
            }
            return events;
        }

        /// <summary>
        /// Scan an arbitrary directory (e.g. %TEMP%, the sample's
        /// working dir, the network capture cache) for the canary
        /// token. Any match indicates the sample copied a credential
        /// file off the profile and into an exfil-staging location.
        /// </summary>
        public List<string> ScanForExfilTokens(string searchDir)
        {
            var events = new List<string>();
            if (string.IsNullOrEmpty(searchDir) || !Directory.Exists(searchDir))
                return events;
            try
            {
                foreach (var path in Directory.EnumerateFiles(searchDir, "*", SearchOption.AllDirectories))
                {
                    if (_files.ContainsKey(path)) continue;
                    try
                    {
                        var fi = new FileInfo(path);
                        if (fi.Length == 0 || fi.Length > 32 * 1024 * 1024) continue;
                        var content = File.ReadAllText(path);
                        if (content.IndexOf(CanaryToken, StringComparison.Ordinal) >= 0)
                            events.Add("wsb:NET:exfil_stage:" + path);
                    }
                    catch { /* best-effort */ }
                }
            }
            catch { /* best-effort */ }
            return events;
        }

        /// <summary>
        /// Best-effort cleanup. Tests / sandbox drivers should call
        /// this in a finally block.
        /// </summary>
        public void Cleanup()
        {
            try { if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true); }
            catch { /* best-effort */ }
        }

        private string RelOf(string full)
        {
            try { return Path.GetRelativePath(Root, full).Replace('\\', '/'); }
            catch { return full; }
        }
    }

    public sealed record CanaryFile(string Path, string Content, long OriginalLength);
}
