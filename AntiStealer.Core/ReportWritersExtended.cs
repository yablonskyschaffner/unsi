using System.Text;
using System.Text.Json;

// EE1–EE7: additional report writers.
//
// EE1  MISP JSON          — Misp event object with attributes grouped by category.
// EE2  OpenIOC 1.1 XML    — FireEye-Mandiant IOC schema with the indicators flattened
//                           into AND/OR boolean blocks.
// EE3  Markdown report    — nice to paste in GitHub issues / Slack.
// EE4  CEF (ArcSight)     — one-liner per hit, `CEF:0|vendor|product|version|signature|name|severity|ext`.
// EE5  Syslog RFC 5424    — message wrapping the CEF line so a Syslog collector can pick it up.
// EE6  CLI autocomplete   — bash/zsh/pwsh completion scripts for the `antistealer` command.
// EE7  Diff-report        — `antistealer diff old.json new.json` → what changed between two runs.

namespace AntiStealerOneExe
{
    public static class ReportWritersExtended
    {
        // ------------------------------------------------------------------
        // EE1 — MISP JSON
        // ------------------------------------------------------------------
        // https://www.circl.lu/doc/misp/book/events.html
        public static string ToMispEvent(IReadOnlyList<AnalysisResult> results, string eventInfo = "AntiStealer batch")
        {
            var attributes = new List<object>();
            int n = 0;
            foreach (var r in results)
            {
                // Each analysis becomes attributes in a single event.
                if (!string.IsNullOrEmpty(r.Sha256))
                    attributes.Add(Att(++n, "Payload delivery", "sha256", r.Sha256, $"{r.FilePath} ({r.RiskLevel})"));
                if (!string.IsNullOrEmpty(r.FilePath))
                    attributes.Add(Att(++n, "External analysis", "filename", Path.GetFileName(r.FilePath), r.RiskLevel));
                foreach (var u in r.UrlsFound.Take(32))
                    attributes.Add(Att(++n, "Network activity", "url", u, "observed"));
                foreach (var ip in r.Ipv4Hits.Take(32))
                    attributes.Add(Att(++n, "Network activity", "ip-dst", ip, "observed"));
                foreach (var d in r.DgaSuspiciousDomains.Take(32))
                    attributes.Add(Att(++n, "Network activity", "domain", d, "DGA-suspicious"));
                foreach (var t in r.TelegramBotTokenHits.Take(8))
                    attributes.Add(Att(++n, "Payload delivery", "telegram-id", t, "tg bot token"));
                foreach (var ttp in r.MitreTtps.Take(32))
                    attributes.Add(Att(++n, "External analysis", "text", ttp, "MITRE ATT&CK TTP"));
            }

            var evt = new
            {
                Event = new
                {
                    info = eventInfo,
                    date = DateTime.UtcNow.ToString("yyyy-MM-dd"),
                    threat_level_id = 2,     // Medium default
                    analysis = 2,            // Completed
                    distribution = 0,        // Your organisation only
                    published = false,
                    Attribute = attributes,
                    Tag = new object[]
                    {
                        new { name = "tlp:amber", colour = "#FFC000" },
                        new { name = "source:antistealer" },
                    },
                },
            };
            return JsonSerializer.Serialize(evt, new JsonSerializerOptions { WriteIndented = true });
        }

        private static object Att(int id, string category, string type, string value, string comment) => new
        {
            id = id.ToString(),
            uuid = Guid.NewGuid().ToString(),
            category,
            type,
            value,
            comment,
            to_ids = true,
            timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
            distribution = "5",
        };

        // ------------------------------------------------------------------
        // EE2 — OpenIOC 1.1 XML
        // ------------------------------------------------------------------
        public static string ToOpenIoc(IReadOnlyList<AnalysisResult> results, string description = "AntiStealer IOC set")
        {
            string id = Guid.NewGuid().ToString();
            string date = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
            var sb = new StringBuilder(64 * 1024);
            sb.AppendLine("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
            sb.AppendLine($"<ioc xmlns=\"http://schemas.mandiant.com/2010/ioc\" id=\"{id}\" last-modified=\"{date}\">");
            sb.AppendLine($"  <short_description>AntiStealer IOC export</short_description>");
            sb.AppendLine($"  <description>{Esc(description)}</description>");
            sb.AppendLine($"  <authored_by>AntiStealer</authored_by>");
            sb.AppendLine($"  <authored_date>{date}</authored_date>");
            sb.AppendLine("  <links/>");
            sb.AppendLine("  <definition>");
            sb.AppendLine("    <Indicator operator=\"OR\" id=\"" + Guid.NewGuid() + "\">");
            foreach (var r in results)
            {
                if (!string.IsNullOrEmpty(r.Sha256)) EmitItem(sb, "FileItem/Sha256sum", r.Sha256);
                foreach (var u in r.UrlsFound.Take(64))    EmitItem(sb, "UrlHistoryItem/URL", u);
                foreach (var ip in r.Ipv4Hits.Take(64))    EmitItem(sb, "PortItem/remoteIP", ip);
                foreach (var d in r.DgaSuspiciousDomains.Take(64)) EmitItem(sb, "DnsEntryItem/Host", d);
                foreach (var t in r.TelegramBotTokenHits.Take(8)) EmitItem(sb, "ProcessItem/arguments", t);
            }
            sb.AppendLine("    </Indicator>");
            sb.AppendLine("  </definition>");
            sb.AppendLine("</ioc>");
            return sb.ToString();
        }

        private static void EmitItem(StringBuilder sb, string search, string content)
        {
            sb.AppendLine($"      <IndicatorItem id=\"{Guid.NewGuid()}\" condition=\"is\">");
            sb.AppendLine($"        <Context document=\"{search.Split('/')[0]}\" search=\"{search}\" type=\"mir\"/>");
            sb.AppendLine($"        <Content type=\"string\">{Esc(content)}</Content>");
            sb.AppendLine("      </IndicatorItem>");
        }

        private static string Esc(string s) =>
            (s ?? "")
              .Replace("&", "&amp;")
              .Replace("<", "&lt;")
              .Replace(">", "&gt;")
              .Replace("\"", "&quot;");

        // ------------------------------------------------------------------
        // EE3 — Markdown report (nice in GitHub issues / Slack / wiki)
        // ------------------------------------------------------------------
        public static string ToMarkdown(IReadOnlyList<AnalysisResult> results)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"# AntiStealer report — {results.Count} file(s)");
            sb.AppendLine();
            sb.AppendLine($"_Generated {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss} UTC_");
            sb.AppendLine();
            sb.AppendLine("| File | Type | Score | Level | Family | SHA-256 |");
            sb.AppendLine("|------|------|-------|-------|--------|---------|");
            foreach (var r in results.OrderByDescending(x => x.RiskScore))
            {
                var name = Path.GetFileName(r.FilePath ?? "");
                string emoji = r.RiskLevel switch
                {
                    "HIGH" => "🔴",
                    "MEDIUM" => "🟠",
                    _ => "🟢",
                };
                sb.AppendLine($"| `{name}` | {r.FileType} | {r.RiskScore}/100 | {emoji} {r.RiskLevel} | {r.FamilyName} | `{r.Sha256}` |");
            }
            sb.AppendLine();
            foreach (var r in results.OrderByDescending(x => x.RiskScore))
            {
                sb.AppendLine($"## {Path.GetFileName(r.FilePath ?? "")} — {r.RiskScore}/100 ({r.RiskLevel})");
                sb.AppendLine();
                if (!string.IsNullOrEmpty(r.FamilyName))
                    sb.AppendLine($"**Family:** {r.FamilyName} (confidence {r.FamilyConfidence:0.##})");
                sb.AppendLine($"**SHA-256:** `{r.Sha256}`");
                if (r.MitreTtps.Count > 0)
                    sb.AppendLine($"**MITRE ATT&CK:** {string.Join(", ", r.MitreTtps.Take(12))}");
                sb.AppendLine();
                void Dump(string h, IReadOnlyCollection<string> hits)
                {
                    if (hits == null || hits.Count == 0) return;
                    sb.AppendLine($"**{h}** ({hits.Count}):");
                    foreach (var x in hits.Take(10)) sb.AppendLine($"- `{x}`");
                    sb.AppendLine();
                }
                Dump("URLs",               r.UrlsFound);
                Dump("Malware self-ID",    r.MalwareSelfIdHits);
                Dump("Telegram exfil",     r.TelegramExfilEndpoints);
                Dump("Game targets",       r.GameTargetHits);
                Dump("Credential paths",   r.CredentialFilePathHits);
                Dump("Wallet paths",       r.CryptoWalletPathHits);
                Dump("Injection",          r.InjectionPrimitives);
                sb.AppendLine("---");
                sb.AppendLine();
            }
            return sb.ToString();
        }

        // ------------------------------------------------------------------
        // EE4 — CEF (Common Event Format, ArcSight)
        // Format: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|ext
        // ------------------------------------------------------------------
        public static string ToCef(IReadOnlyList<AnalysisResult> results)
        {
            var sb = new StringBuilder();
            foreach (var r in results)
            {
                int severity = r.RiskLevel switch { "HIGH" => 10, "MEDIUM" => 6, _ => 3 };
                string name   = string.IsNullOrEmpty(r.FamilyName) ? "Suspicious sample" : r.FamilyName;
                string ext    = string.Join(" ", new[]
                {
                    $"fname={CefEsc(Path.GetFileName(r.FilePath ?? ""))}",
                    $"fileHash={r.Sha256}",
                    $"cs1Label=RiskScore cs1={r.RiskScore}",
                    $"cs2Label=RiskLevel cs2={r.RiskLevel}",
                    $"cs3Label=FileType cs3={CefEsc(r.FileType)}",
                    $"cs4Label=TTPs cs4={string.Join(",", r.MitreTtps.Take(10))}",
                    $"cs5Label=URLs cs5={CefEsc(string.Join(",", r.UrlsFound.Take(5)))}",
                });
                sb.AppendLine($"CEF:0|AntiStealer|AntiStealer|1.0|{r.RiskLevel}|{CefEsc(name)}|{severity}|{ext}");
            }
            return sb.ToString();
        }

        private static string CefEsc(string s) => (s ?? "").Replace("\\", "\\\\").Replace("|", "\\|").Replace("=", "\\=");

        // ------------------------------------------------------------------
        // EE5 — RFC 5424 Syslog wrapping CEF payload
        // ------------------------------------------------------------------
        public static string ToSyslogRfc5424(IReadOnlyList<AnalysisResult> results, string host = "antistealer")
        {
            var sb = new StringBuilder();
            foreach (var line in ToCef(results).Split('\n'))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                // <pri>1 timestamp host app procid msgid MSG
                // PRI = 13*8 + 4 = 108 (local0.warning). Not overly important for SOCs.
                string ts = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
                sb.AppendLine($"<108>1 {ts} {host} antistealer - - - {line.Trim()}");
            }
            return sb.ToString();
        }

        // ------------------------------------------------------------------
        // EE6 — CLI autocomplete scripts (bash / zsh / powershell)
        // ------------------------------------------------------------------
        public static string ToBashCompletion() => @"
# AntiStealer bash completion
_antistealer_complete() {
  local cur prev words cword
  _init_completion || return
  case ""${prev}"" in
    --format) COMPREPLY=( $(compgen -W ""text json html pdf csv markdown misp openioc cef syslog stix sarif"" -- ""$cur"") ); return ;;
    --report) COMPREPLY=( $(compgen -f -- ""$cur"") ); return ;;
    -i|--input) COMPREPLY=( $(compgen -f -- ""$cur"") ); return ;;
  esac
  COMPREPLY=( $(compgen -W ""scan diff watch serve version --format --report -i --input --recursive --jobs --help"" -- ""$cur"") )
}
complete -F _antistealer_complete antistealer
";

        public static string ToZshCompletion() => @"
#compdef antistealer
_arguments \
  '(-i --input)'{-i,--input}'[file or directory]:file:_files' \
  '--format[output format]:format:(text json html pdf csv markdown misp openioc cef syslog stix sarif)' \
  '--report[output path]:path:_files' \
  '--recursive[walk directories]' \
  '--jobs[concurrency]:n:' \
  '*:command:(scan diff watch serve version)'
";

        public static string ToPowerShellCompletion() => @"
Register-ArgumentCompleter -Native -CommandName antistealer -ScriptBlock {
  param($wordToComplete, $commandAst, $cursorPosition)
  $commands = @('scan','diff','watch','serve','version','--format','--report','--recursive','--jobs','-i','--input','--help')
  $commands | Where-Object { $_ -like ""$wordToComplete*"" }
}
";

        // ------------------------------------------------------------------
        // EE7 — Diff two JSON reports and render a human-readable summary.
        // ------------------------------------------------------------------
        public sealed class DiffSummary
        {
            public List<string> AddedFiles     { get; set; } = new();
            public List<string> RemovedFiles   { get; set; } = new();
            public List<string> ChangedLevel   { get; set; } = new();    // "file.exe: MEDIUM → HIGH"
            public List<string> ChangedScore   { get; set; } = new();    // "file.exe: 36 → 100"
            public List<string> NewUrls        { get; set; } = new();
            public List<string> NewTtps        { get; set; } = new();
        }

        public static DiffSummary DiffJsonReports(string oldJson, string newJson)
        {
            var oldDoc = JsonDocument.Parse(oldJson);
            var newDoc = JsonDocument.Parse(newJson);
            var oldResults = oldDoc.RootElement.TryGetProperty("results", out var or) ? or : oldDoc.RootElement;
            var newResults = newDoc.RootElement.TryGetProperty("results", out var nr) ? nr : newDoc.RootElement;

            var oldByHash = new Dictionary<string, JsonElement>();
            var newByHash = new Dictionary<string, JsonElement>();
            // Accept both PascalCase (default serializer) and camelCase keys.
            static JsonElement? TryProp(JsonElement e, params string[] names)
            {
                foreach (var n in names)
                    if (e.TryGetProperty(n, out var v)) return v;
                return null;
            }
            string? GetHash(JsonElement r) => TryProp(r, "Sha256", "sha256")?.GetString();

            foreach (var r in oldResults.EnumerateArray())
            {
                var h = GetHash(r);
                if (!string.IsNullOrEmpty(h)) oldByHash[h] = r;
            }
            foreach (var r in newResults.EnumerateArray())
            {
                var h = GetHash(r);
                if (!string.IsNullOrEmpty(h)) newByHash[h] = r;
            }

            var d = new DiffSummary();
            foreach (var kv in newByHash)
            {
                if (!oldByHash.TryGetValue(kv.Key, out var old))
                {
                    string name = TryProp(kv.Value, "FilePath", "filePath")?.GetString() ?? kv.Key;
                    d.AddedFiles.Add(name);
                    continue;
                }
                string oldLevel = TryProp(old, "RiskLevel", "riskLevel")?.GetString() ?? "";
                string newLevel = TryProp(kv.Value, "RiskLevel", "riskLevel")?.GetString() ?? "";
                int oldScore = TryProp(old, "RiskScore", "riskScore")?.GetInt32() ?? 0;
                int newScore = TryProp(kv.Value, "RiskScore", "riskScore")?.GetInt32() ?? 0;
                string name2 = TryProp(kv.Value, "FilePath", "filePath")?.GetString() ?? kv.Key;
                if (oldLevel != newLevel) d.ChangedLevel.Add($"{name2}: {oldLevel} → {newLevel}");
                if (oldScore  != newScore) d.ChangedScore.Add($"{name2}: {oldScore} → {newScore}");

                var oldUrls = CollectStrings(old, "UrlsFound", "urlsFound");
                var newUrls = CollectStrings(kv.Value, "UrlsFound", "urlsFound");
                foreach (var u in newUrls.Except(oldUrls)) d.NewUrls.Add($"{name2}: +{u}");
                var oldTtps = CollectStrings(old, "MitreTtps", "mitreTtps");
                var newTtps = CollectStrings(kv.Value, "MitreTtps", "mitreTtps");
                foreach (var t in newTtps.Except(oldTtps)) d.NewTtps.Add($"{name2}: +{t}");
            }
            foreach (var kv in oldByHash)
                if (!newByHash.ContainsKey(kv.Key))
                {
                    string name = TryProp(kv.Value, "FilePath", "filePath")?.GetString() ?? kv.Key;
                    d.RemovedFiles.Add(name);
                }
            return d;
        }

        public static string DiffToMarkdown(DiffSummary d)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# AntiStealer diff");
            sb.AppendLine();
            Section("Added files",   d.AddedFiles);
            Section("Removed files", d.RemovedFiles);
            Section("Changed level", d.ChangedLevel);
            Section("Changed score", d.ChangedScore);
            Section("New URLs",      d.NewUrls);
            Section("New TTPs",      d.NewTtps);
            return sb.ToString();

            void Section(string title, List<string> items)
            {
                if (items.Count == 0) return;
                sb.AppendLine($"## {title} ({items.Count})");
                foreach (var x in items) sb.AppendLine($"- {x}");
                sb.AppendLine();
            }
        }

        private static HashSet<string> CollectStrings(JsonElement obj, params string[] props)
        {
            var set = new HashSet<string>();
            foreach (var prop in props)
            {
                if (obj.TryGetProperty(prop, out var el) && el.ValueKind == JsonValueKind.Array)
                {
                    foreach (var x in el.EnumerateArray())
                        if (x.ValueKind == JsonValueKind.String) set.Add(x.GetString() ?? "");
                    break;
                }
            }
            return set;
        }
    }
}
