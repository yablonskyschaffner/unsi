using System.Collections.Generic;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

// Section 11.5 – 11.11. New report writers added in PR 7.
//
//   11.5  XLSX        – minimal SpreadsheetML (Open XML) workbook built
//                       with System.IO.Compression only — NO NuGet package
//                       (zero-dep policy, see plan).
//   11.6  ECS NDJSON  – one JSON document per result, Elastic Common Schema
//                       fields. Ingestable by Filebeat / Logstash / Vector.
//   11.7  Splunk HEC  – {time, host, source, sourcetype, event:{ECS body}}.
//                       Includes a PushToSplunkAsync helper.
//   11.8  Webhooks    – Slack / Microsoft Teams / Discord JSON payloads.
//                       Includes a PostToWebhookAsync helper.
//   11.9  Jira        – Cloud REST v3 issue create payload (Atlassian
//                       Document Format description).
//   11.10 Suricata    – IDS .rules lines for URL / IP / domain IOCs.
//   11.11 Diff HTML   – render DiffSummary as an interactive HTML page.
namespace AntiStealerOneExe
{
    public static class ReportsV2
    {
        // ─────────────────────────────────────────────────────────────────
        // 11.5 — XLSX writer (pure System.IO.Compression, no NuGet)
        // ─────────────────────────────────────────────────────────────────
        public static byte[] ToXlsx(IReadOnlyList<AnalysisResult> results)
        {
            // Build worksheet cells once so we know the row count.
            var rows = new List<string[]>(results.Count + 1)
            {
                new[] { "File", "Type", "RiskScore", "RiskLevel", "Family", "Confidence", "Net", "Packed", "Signed",
                        "Heuristics", "URLs", "API", "IOCs", "SHA256", "ImpHash", "MITRE", "Reasons" },
            };
            foreach (var r in results)
            {
                rows.Add(new[]
                {
                    r.FilePath ?? "",
                    r.FileType ?? "",
                    r.RiskScore.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    r.RiskLevel ?? "",
                    r.FamilyName ?? "",
                    r.FamilyConfidence.ToString("0", System.Globalization.CultureInfo.InvariantCulture),
                    (r.NetDllHits.Count + r.UrlsFound.Count).ToString(System.Globalization.CultureInfo.InvariantCulture),
                    r.PackerHints.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    r.IsSigned ? "1" : "0",
                    r.CustomHeuristicHits.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    r.UrlsFound.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    r.SuspiciousApiHits.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    r.TotalIocHits.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    r.Sha256 ?? "",
                    r.ImpHash ?? "",
                    string.Join(",", r.MitreTtps),
                    r.ReasonsShort ?? "",
                });
            }

            var sheet = BuildSheetXml(rows);
            const string contentTypes =
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
                "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">" +
                "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>" +
                "<Default Extension=\"xml\" ContentType=\"application/xml\"/>" +
                "<Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>" +
                "<Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>" +
                "</Types>";
            const string packageRels =
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
                "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">" +
                "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/>" +
                "</Relationships>";
            const string workbookXml =
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
                "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"" +
                " xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">" +
                "<sheets><sheet name=\"AntiStealer\" sheetId=\"1\" r:id=\"rId1\"/></sheets>" +
                "</workbook>";
            const string workbookRels =
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
                "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">" +
                "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/>" +
                "</Relationships>";

            using var ms = new MemoryStream();
            using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
            {
                WriteEntry(zip, "[Content_Types].xml",            contentTypes);
                WriteEntry(zip, "_rels/.rels",                    packageRels);
                WriteEntry(zip, "xl/workbook.xml",                workbookXml);
                WriteEntry(zip, "xl/_rels/workbook.xml.rels",     workbookRels);
                WriteEntry(zip, "xl/worksheets/sheet1.xml",       sheet);
            }
            return ms.ToArray();
        }

        private static void WriteEntry(ZipArchive zip, string path, string content)
        {
            var entry = zip.CreateEntry(path, CompressionLevel.Optimal);
            using var w = new StreamWriter(entry.Open(), new UTF8Encoding(false));
            w.Write(content);
        }

        private static string BuildSheetXml(IReadOnlyList<string[]> rows)
        {
            var sb = new StringBuilder(64 * 1024);
            sb.Append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>");
            sb.Append("<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData>");
            for (int rowIdx = 0; rowIdx < rows.Count; rowIdx++)
            {
                int excelRow = rowIdx + 1;
                sb.Append("<row r=\"").Append(excelRow).Append("\">");
                var cols = rows[rowIdx];
                for (int c = 0; c < cols.Length; c++)
                {
                    string cellRef = ExcelColumnName(c) + excelRow;
                    string val = cols[c] ?? "";
                    // Numbers go in as <v>, everything else as inline strings.
                    if (rowIdx > 0 && double.TryParse(val, System.Globalization.NumberStyles.Any,
                        System.Globalization.CultureInfo.InvariantCulture, out _) && val.Length < 16)
                    {
                        sb.Append("<c r=\"").Append(cellRef).Append("\"><v>").Append(XmlEsc(val)).Append("</v></c>");
                    }
                    else
                    {
                        sb.Append("<c r=\"").Append(cellRef).Append("\" t=\"inlineStr\"><is><t xml:space=\"preserve\">")
                          .Append(XmlEsc(val)).Append("</t></is></c>");
                    }
                }
                sb.Append("</row>");
            }
            sb.Append("</sheetData></worksheet>");
            return sb.ToString();
        }

        // 0→"A", 1→"B", ..., 25→"Z", 26→"AA", ...
        private static string ExcelColumnName(int index)
        {
            var sb = new StringBuilder();
            int i = index;
            do
            {
                sb.Insert(0, (char)('A' + (i % 26)));
                i = (i / 26) - 1;
            } while (i >= 0);
            return sb.ToString();
        }

        private static string XmlEsc(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var sb = new StringBuilder(s.Length);
            foreach (var c in s)
            {
                switch (c)
                {
                    case '&':  sb.Append("&amp;");  break;
                    case '<':  sb.Append("&lt;");   break;
                    case '>':  sb.Append("&gt;");   break;
                    case '"':  sb.Append("&quot;"); break;
                    case '\'': sb.Append("&apos;"); break;
                    default:
                        // Strip XML 1.0 illegal control chars (we keep \t \n \r).
                        if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') sb.Append(' ');
                        else sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }

        // ─────────────────────────────────────────────────────────────────
        // 11.6 — Elastic Common Schema NDJSON. One ECS document per result.
        // ─────────────────────────────────────────────────────────────────
        public static string ToEcsNdjson(IReadOnlyList<AnalysisResult> results, string? host = null)
        {
            host ??= System.Environment.MachineName;
            var sb = new StringBuilder(16 * 1024);
            foreach (var r in results)
            {
                sb.AppendLine(BuildEcsJson(r, host));
            }
            return sb.ToString();
        }

        // Build one ECS JSON document.
        public static string BuildEcsJson(AnalysisResult r, string? host = null)
        {
            host ??= System.Environment.MachineName;
            string eventType = r.RiskScore >= 70 ? "alert"
                            : r.RiskScore >= 40 ? "alert"
                            : "info";
            var doc = new Dictionary<string, object?>
            {
                ["@timestamp"]   = System.DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                ["ecs"]          = new { version = "8.11.0" },
                ["agent"]        = new { name = "antistealer", type = "antistealer", version = "1.0" },
                ["event"]        = new
                {
                    kind     = eventType,
                    module   = "antistealer",
                    dataset  = "antistealer.scan",
                    action   = "static-analysis",
                    category = new[] { "malware", "intrusion_detection" },
                    type     = new[] { r.RiskScore >= 40 ? "indicator" : "info" },
                    outcome  = "success",
                    severity = r.RiskScore,
                    reason   = r.ReasonsShort ?? "",
                    risk_score = r.RiskScore,
                    risk_score_norm = r.RiskScore,
                },
                ["host"]         = new { name = host, hostname = host },
                ["message"]      = $"[{r.RiskLevel}] {Path.GetFileName(r.FilePath ?? "")} risk={r.RiskScore} family={r.FamilyName} reasons={r.ReasonsShort}",
                ["labels"]       = new { risk_level = r.RiskLevel, file_type = r.FileType, family = r.FamilyName },
                ["file"]         = new
                {
                    name       = string.IsNullOrEmpty(r.FilePath) ? null : Path.GetFileName(r.FilePath),
                    path       = r.FilePath,
                    size       = r.Size,
                    extension  = string.IsNullOrEmpty(r.FilePath) ? null : Path.GetExtension(r.FilePath)?.TrimStart('.'),
                    hash       = new
                    {
                        sha256  = string.IsNullOrEmpty(r.Sha256)  ? null : r.Sha256,
                        imphash = string.IsNullOrEmpty(r.ImpHash) ? null : r.ImpHash,
                    },
                    code_signature = new
                    {
                        exists      = r.IsSigned,
                        subject_name = r.Signer,
                        valid       = r.SignerChainValid,
                    },
                    pe = new
                    {
                        imphash       = string.IsNullOrEmpty(r.ImpHash) ? null : r.ImpHash,
                        company       = r.VersionInfo.TryGetValue("CompanyName", out var cn) ? cn : null,
                        original_file_name = r.VersionInfo.TryGetValue("OriginalFilename", out var of) ? of : null,
                    },
                },
                ["threat"]       = new
                {
                    framework = "MITRE ATT&CK",
                    technique = r.MitreTtps.Count == 0 ? null : r.MitreTtps.Take(32).Select(t => new { id = t }).ToArray(),
                    software  = string.IsNullOrEmpty(r.FamilyName) ? null : new
                    {
                        name = r.FamilyName,
                        type = new[] { "Trojan", "Stealer" },
                    },
                    indicator = new
                    {
                        url     = r.UrlsFound.Take(16).Select(u => new { full = u }).ToArray(),
                        ip      = r.Ipv4Hits.Take(16).ToArray(),
                        type    = "file",
                        confidence = (r.FamilyConfidence >= 0.7) ? "High"
                                  : (r.FamilyConfidence >= 0.4) ? "Medium"
                                  : "Low",
                    },
                },
                ["antistealer"]  = new
                {
                    capabilities = r.CapabilityScores,
                    reasons      = r.ReasonsShort,
                    risk_score   = r.RiskScore,
                    risk_level   = r.RiskLevel,
                },
            };
            return JsonSerializer.Serialize(doc, EcsJsonOpts);
        }

        private static readonly JsonSerializerOptions EcsJsonOpts = new()
        {
            WriteIndented = false,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        };

        // ─────────────────────────────────────────────────────────────────
        // 11.7 — Splunk HEC envelopes (one JSON document per event, on
        //         separate lines, as required by the /services/collector
        //         endpoint).
        // ─────────────────────────────────────────────────────────────────
        public static string ToSplunkHec(IReadOnlyList<AnalysisResult> results, string? host = null, string source = "antistealer", string sourcetype = "antistealer:scan", string index = "main")
        {
            host ??= System.Environment.MachineName;
            var sb = new StringBuilder(16 * 1024);
            foreach (var r in results)
            {
                var doc = new Dictionary<string, object?>
                {
                    ["time"]       = System.DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0,
                    ["host"]       = host,
                    ["source"]     = source,
                    ["sourcetype"] = sourcetype,
                    ["index"]      = index,
                    ["event"]      = JsonDocument.Parse(BuildEcsJson(r, host)).RootElement.Clone(),
                };
                sb.AppendLine(JsonSerializer.Serialize(doc, EcsJsonOpts));
            }
            return sb.ToString();
        }

        // POST to Splunk's HTTP Event Collector. Returns the response status code.
        // hecUrl example: https://splunk.example.com:8088/services/collector
        public static async Task<HttpStatusCode> PushToSplunkAsync(string hecUrl, string hecToken, IReadOnlyList<AnalysisResult> results, HttpClient? client = null, CancellationToken ct = default)
        {
            client ??= s_httpClient.Value;
            string body = ToSplunkHec(results);
            using var req = new HttpRequestMessage(HttpMethod.Post, hecUrl)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };
            req.Headers.Authorization = new AuthenticationHeaderValue("Splunk", hecToken);
            using var resp = await client.SendAsync(req, ct).ConfigureAwait(false);
            return resp.StatusCode;
        }

        // ─────────────────────────────────────────────────────────────────
        // 11.8 — Slack / Teams / Discord webhook payloads.
        //         All three use a single `--webhook URL` flag; we auto-detect
        //         the platform by URL host so the same flag works for all.
        // ─────────────────────────────────────────────────────────────────
        public enum WebhookKind { Slack, Teams, Discord, Generic }

        public static WebhookKind DetectWebhookKind(string url)
        {
            if (string.IsNullOrEmpty(url)) return WebhookKind.Generic;
            string u = url.ToLowerInvariant();
            if (u.Contains("hooks.slack.com"))            return WebhookKind.Slack;
            if (u.Contains("webhook.office.com")
             || u.Contains("outlook.office.com/webhook")) return WebhookKind.Teams;
            if (u.Contains("discord.com/api/webhooks")
             || u.Contains("discordapp.com/api/webhooks"))return WebhookKind.Discord;
            return WebhookKind.Generic;
        }

        public static string ToWebhookPayload(IReadOnlyList<AnalysisResult> results, WebhookKind kind)
        {
            // Build top summary regardless of platform.
            int total = results.Count;
            int high  = results.Count(r => r.RiskScore >= 70);
            int med   = results.Count(r => r.RiskScore >= 40 && r.RiskScore < 70);
            int low   = total - high - med;
            string headline = $"AntiStealer scan: {high} HIGH, {med} MEDIUM, {low} LOW ({total} files)";

            var top5 = results
                .OrderByDescending(x => x.RiskScore)
                .Take(5)
                .ToArray();

            return kind switch
            {
                WebhookKind.Slack   => BuildSlackPayload(headline, top5),
                WebhookKind.Teams   => BuildTeamsPayload(headline, top5),
                WebhookKind.Discord => BuildDiscordPayload(headline, top5),
                _                   => BuildGenericPayload(headline, top5),
            };
        }

        private static string BuildSlackPayload(string headline, AnalysisResult[] top5)
        {
            var blocks = new List<object>
            {
                new { type = "header",  text = new { type = "plain_text", text = headline } },
                new { type = "section", text = new { type = "mrkdwn",      text = $"*Generated:* {System.DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC" } },
            };
            foreach (var r in top5)
            {
                string emoji = r.RiskScore >= 70 ? ":rotating_light:" : r.RiskScore >= 40 ? ":warning:" : ":information_source:";
                blocks.Add(new
                {
                    type = "section",
                    text = new
                    {
                        type = "mrkdwn",
                        text = $"{emoji} *{Esc(Path.GetFileName(r.FilePath ?? ""))}* — `{r.RiskScore}/100` ({r.RiskLevel})\n" +
                               $"_{Esc(r.ReasonsShort ?? "")}_\n" +
                               (string.IsNullOrEmpty(r.FamilyName) ? "" : $"Family: `{r.FamilyName}`\n") +
                               (string.IsNullOrEmpty(r.Sha256)     ? "" : $"SHA-256: `{r.Sha256}`"),
                    },
                });
            }
            return JsonSerializer.Serialize(new { text = headline, blocks }, EcsJsonOpts);

            static string Esc(string s) => (s ?? "").Replace("<", "&lt;").Replace(">", "&gt;").Replace("&", "&amp;");
        }

        private static string BuildTeamsPayload(string headline, AnalysisResult[] top5)
        {
            var sections = new List<object>
            {
                new
                {
                    activityTitle    = headline,
                    activitySubtitle = $"Generated {System.DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC",
                    markdown         = true,
                },
            };
            foreach (var r in top5)
            {
                sections.Add(new
                {
                    activityTitle = $"**{Path.GetFileName(r.FilePath ?? "")}**",
                    facts = new object[]
                    {
                        new { name = "Risk",    value = $"{r.RiskScore}/100 ({r.RiskLevel})" },
                        new { name = "Family",  value = string.IsNullOrEmpty(r.FamilyName) ? "—" : r.FamilyName },
                        new { name = "SHA-256", value = string.IsNullOrEmpty(r.Sha256)     ? "—" : r.Sha256 },
                        new { name = "Reasons", value = r.ReasonsShort ?? "" },
                    },
                    markdown = true,
                });
            }
            var card = new Dictionary<string, object?>
            {
                ["@type"]      = "MessageCard",
                ["@context"]   = "http://schema.org/extensions",
                ["themeColor"] = top5.Length > 0 && top5[0].RiskScore >= 70 ? "C0392B"
                              : top5.Length > 0 && top5[0].RiskScore >= 40 ? "E67E22"
                              : "27AE60",
                ["summary"]    = headline,
                ["title"]      = headline,
                ["sections"]   = sections,
            };
            return JsonSerializer.Serialize(card, EcsJsonOpts);
        }

        private static string BuildDiscordPayload(string headline, AnalysisResult[] top5)
        {
            var embeds = new List<object>();
            foreach (var r in top5)
            {
                int color = r.RiskScore >= 70 ? 0xC0392B : r.RiskScore >= 40 ? 0xE67E22 : 0x27AE60;
                embeds.Add(new
                {
                    title       = $"{Path.GetFileName(r.FilePath ?? "")} — {r.RiskScore}/100 {r.RiskLevel}",
                    description = string.IsNullOrEmpty(r.ReasonsShort) ? "no strong indicators" : r.ReasonsShort,
                    color,
                    fields = new object[]
                    {
                        new { name = "Family",  value = string.IsNullOrEmpty(r.FamilyName) ? "—" : r.FamilyName, inline = true },
                        new { name = "Type",    value = r.FileType ?? "?", inline = true },
                        new { name = "SHA-256", value = string.IsNullOrEmpty(r.Sha256) ? "—" : r.Sha256, inline = false },
                    },
                });
            }
            return JsonSerializer.Serialize(new
            {
                username = "AntiStealer",
                content  = headline,
                embeds,
            }, EcsJsonOpts);
        }

        private static string BuildGenericPayload(string headline, AnalysisResult[] top5) =>
            JsonSerializer.Serialize(new
            {
                title    = headline,
                summary  = headline,
                top      = top5.Select(r => new
                {
                    file    = Path.GetFileName(r.FilePath ?? ""),
                    risk    = r.RiskScore,
                    level   = r.RiskLevel,
                    family  = r.FamilyName,
                    sha256  = r.Sha256,
                    reasons = r.ReasonsShort,
                }).ToArray(),
            }, EcsJsonOpts);

        public static async Task<HttpStatusCode> PostToWebhookAsync(string url, IReadOnlyList<AnalysisResult> results, HttpClient? client = null, CancellationToken ct = default)
        {
            client ??= s_httpClient.Value;
            var kind = DetectWebhookKind(url);
            string body = ToWebhookPayload(results, kind);
            using var resp = await client.PostAsync(url, new StringContent(body, Encoding.UTF8, "application/json"), ct).ConfigureAwait(false);
            return resp.StatusCode;
        }

        // ─────────────────────────────────────────────────────────────────
        // 11.9 — Jira Cloud REST v3 "create issue" payload.
        //         Auto-creates one ticket per HIGH-risk result.
        // ─────────────────────────────────────────────────────────────────
        public static string ToJiraIssuePayload(AnalysisResult r, string projectKey, string issueType = "Bug", string? assignee = null)
        {
            string title = $"[AntiStealer] {Path.GetFileName(r.FilePath ?? "unknown")} — {r.RiskScore}/100 {r.RiskLevel}";
            string priority = r.RiskScore >= 70 ? "Highest" : r.RiskScore >= 40 ? "Medium" : "Low";

            // Atlassian Document Format (ADF) description.
            var paragraphs = new List<object>
            {
                AdfParagraph($"Risk score: {r.RiskScore}/100 ({r.RiskLevel})"),
                AdfParagraph($"Family: {(string.IsNullOrEmpty(r.FamilyName) ? "—" : r.FamilyName)}  Confidence: {r.FamilyConfidence:0}%"),
                AdfParagraph($"SHA-256: {r.Sha256}"),
                AdfParagraph($"ImpHash: {r.ImpHash}"),
                AdfParagraph($"Reasons: {r.ReasonsShort ?? ""}"),
            };
            if (r.UrlsFound.Count > 0)
                paragraphs.Add(AdfParagraph("URLs: " + string.Join(", ", r.UrlsFound.Take(8))));
            if (r.Ipv4Hits.Count > 0)
                paragraphs.Add(AdfParagraph("IPs: "  + string.Join(", ", r.Ipv4Hits.Take(8))));
            if (r.MitreTtps.Count > 0)
                paragraphs.Add(AdfParagraph("MITRE: " + string.Join(", ", r.MitreTtps.Take(12))));

            var labels = new List<string> { "antistealer", $"risk-{r.RiskLevel.ToLowerInvariant()}" };
            if (!string.IsNullOrEmpty(r.FamilyName))
                labels.Add("family-" + Regex.Replace(r.FamilyName.ToLowerInvariant(), "[^a-z0-9]+", "-"));

            var fields = new Dictionary<string, object?>
            {
                ["project"]   = new { key = projectKey },
                ["summary"]   = title,
                ["issuetype"] = new { name = issueType },
                ["priority"]  = new { name = priority },
                ["labels"]    = labels,
                ["description"] = new
                {
                    type    = "doc",
                    version = 1,
                    content = paragraphs,
                },
            };
            if (!string.IsNullOrEmpty(assignee))
                fields["assignee"] = new { accountId = assignee };

            return JsonSerializer.Serialize(new { fields }, EcsJsonOpts);
        }

        private static object AdfParagraph(string text) => new
        {
            type    = "paragraph",
            content = new object[]
            {
                new { type = "text", text },
            },
        };

        // POST to Jira Cloud REST v3 — basic auth (email + API token).
        // baseUrl example: https://example.atlassian.net
        public static async Task<HttpStatusCode> PostToJiraAsync(string baseUrl, string email, string apiToken, AnalysisResult r, string projectKey, HttpClient? client = null, CancellationToken ct = default)
        {
            client ??= s_httpClient.Value;
            string body = ToJiraIssuePayload(r, projectKey);
            using var req = new HttpRequestMessage(HttpMethod.Post, baseUrl.TrimEnd('/') + "/rest/api/3/issue")
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };
            string credentials = System.Convert.ToBase64String(Encoding.UTF8.GetBytes(email + ":" + apiToken));
            req.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
            using var resp = await client.SendAsync(req, ct).ConfigureAwait(false);
            return resp.StatusCode;
        }

        // ─────────────────────────────────────────────────────────────────
        // 11.10 — Suricata IDS rules from URL / IP / domain IOCs.
        //          Output is a `.rules` file that can be loaded with
        //          `suricata -S antistealer.rules` (or copied into
        //          `/etc/suricata/rules/`).
        // ─────────────────────────────────────────────────────────────────
        public static string ToSuricataRules(IReadOnlyList<AnalysisResult> results, int sidStart = 9_000_000)
        {
            var seenIps    = new HashSet<string>();
            var seenUrls   = new HashSet<string>();
            var seenHosts  = new HashSet<string>();
            var sb = new StringBuilder();
            sb.AppendLine("# AntiStealer — auto-generated Suricata rules");
            sb.AppendLine("# Each rule references the originating SHA-256 in metadata. Tune sid range");
            sb.AppendLine("# (default 9_000_000+) and severity (msg suffix) before deploying.");
            int sid = sidStart;
            foreach (var r in results)
            {
                if (r.RiskScore < 40) continue; // only suspicious / high
                string risk = r.RiskScore >= 70 ? "HIGH" : "MEDIUM";
                foreach (var ip in r.Ipv4Hits)
                {
                    if (string.IsNullOrWhiteSpace(ip)) continue;
                    if (!seenIps.Add(ip)) continue;
                    sb.AppendLine(
                        $"alert ip any any -> {ip} any (msg:\"ANTISTEALER {risk} C2 IP {ip}\"; " +
                        $"classtype:trojan-activity; reference:url,https://github.com/hatawares1234/antistealer; " +
                        $"metadata:antistealer,risk {risk},sha256 {r.Sha256}; sid:{sid++}; rev:1;)");
                }
                foreach (var url in r.UrlsFound)
                {
                    if (string.IsNullOrWhiteSpace(url) || url.Length > 1024) continue;
                    if (!seenUrls.Add(url)) continue;
                    var host = ExtractHost(url);
                    if (!string.IsNullOrEmpty(host) && seenHosts.Add(host))
                    {
                        sb.AppendLine(
                            $"alert dns any any -> any any (msg:\"ANTISTEALER {risk} DNS lookup {SanitizeForSuricata(host)}\"; " +
                            $"dns.query; content:\"{SanitizeForSuricata(host)}\"; nocase; " +
                            $"classtype:trojan-activity; metadata:antistealer,risk {risk},sha256 {r.Sha256}; " +
                            $"sid:{sid++}; rev:1;)");
                    }
                    sb.AppendLine(
                        $"alert http any any -> any any (msg:\"ANTISTEALER {risk} suspicious URL\"; " +
                        $"http.uri; content:\"{SanitizeForSuricata(url)}\"; nocase; " +
                        $"classtype:trojan-activity; metadata:antistealer,risk {risk},sha256 {r.Sha256}; " +
                        $"sid:{sid++}; rev:1;)");
                }
            }
            return sb.ToString();
        }

        private static string ExtractHost(string url)
        {
            // Pull host out of `scheme://host[:port]/...`. Tolerant — input is
            // a free-form string from the analyzer, not necessarily a URI.
            var m = Regex.Match(url, @"^(?:[a-z][a-z0-9+\-.]*://)?([^/:?#\s]+)", RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value : "";
        }

        // Strip characters that would terminate a Suricata content: pattern.
        private static string SanitizeForSuricata(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var sb = new StringBuilder(s.Length);
            foreach (var c in s)
            {
                if (c == '"' || c == ';' || c == '\\' || c < 0x20 || c > 0x7E) sb.Append('?');
                else sb.Append(c);
            }
            return sb.ToString();
        }

        // ─────────────────────────────────────────────────────────────────
        // 11.11 — Diff-report as interactive HTML.
        //          Inputs are the same DiffSummary produced by
        //          ReportWritersExtended.DiffJsonReports.
        // ─────────────────────────────────────────────────────────────────
        public static string DiffToHtml(ReportWritersExtended.DiffSummary d)
        {
            var sb = new StringBuilder(16 * 1024);
            sb.AppendLine("<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\"/>");
            sb.AppendLine("<title>AntiStealer diff</title>");
            sb.AppendLine("<style>");
            sb.AppendLine(":root{--bg:#fafafa;--fg:#222;--border:#ddd;--card:#fff;--muted:#666;--add:#27ae60;--rem:#c0392b;--chg:#e67e22}");
            sb.AppendLine("@media (prefers-color-scheme:dark){:root{--bg:#1a1a1a;--fg:#e6e6e6;--border:#333;--card:#222;--muted:#999;--add:#27ae60;--rem:#c0392b;--chg:#e67e22}}");
            sb.AppendLine("body{font-family:system-ui,-apple-system,sans-serif;margin:24px;color:var(--fg);background:var(--bg)}");
            sb.AppendLine("h1{font-size:22px}h2{font-size:16px;border-top:1px solid var(--border);padding-top:12px;margin-top:24px}");
            sb.AppendLine("ul{list-style:none;padding:0}li{padding:6px 10px;border-left:3px solid var(--muted);margin:4px 0;background:var(--card);border-radius:0 4px 4px 0;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}");
            sb.AppendLine("li.add{border-left-color:var(--add)} li.rem{border-left-color:var(--rem)} li.chg{border-left-color:var(--chg)}");
            sb.AppendLine(".count{display:inline-block;padding:1px 8px;border-radius:8px;background:var(--muted);color:#fff;font-size:12px;margin-left:8px}");
            sb.AppendLine(".empty{color:var(--muted);font-style:italic}");
            sb.AppendLine(".controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0 16px}");
            sb.AppendLine(".controls input{padding:6px 10px;border:1px solid var(--border);border-radius:4px;background:var(--bg);color:var(--fg);min-width:240px}");
            sb.AppendLine("</style></head><body>");
            sb.AppendLine($"<h1>AntiStealer diff — {System.DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC</h1>");
            sb.AppendLine("<div class=\"controls\"><input id=\"q\" type=\"text\" placeholder=\"Фильтр…\"/></div>");

            Section("Added files",   "add", d.AddedFiles);
            Section("Removed files", "rem", d.RemovedFiles);
            Section("Changed level", "chg", d.ChangedLevel);
            Section("Changed score", "chg", d.ChangedScore);
            Section("New URLs",      "add", d.NewUrls);
            Section("New TTPs",      "add", d.NewTtps);

            sb.AppendLine("<script>");
            sb.AppendLine("document.getElementById('q').addEventListener('input',function(e){var t=(e.target.value||'').toLowerCase();document.querySelectorAll('li').forEach(function(li){li.style.display=(!t||li.textContent.toLowerCase().indexOf(t)>=0)?'':'none';});});");
            sb.AppendLine("</script>");
            sb.AppendLine("</body></html>");
            return sb.ToString();

            void Section(string title, string cls, List<string> items)
            {
                sb.AppendLine($"<h2>{HtmlEsc(title)}<span class=\"count\">{items.Count}</span></h2>");
                if (items.Count == 0)
                {
                    sb.AppendLine("<p class=\"empty\">No changes.</p>");
                    return;
                }
                sb.AppendLine("<ul>");
                foreach (var x in items) sb.AppendLine($"<li class=\"{cls}\">{HtmlEsc(x)}</li>");
                sb.AppendLine("</ul>");
            }
        }

        private static string HtmlEsc(string s) =>
            string.IsNullOrEmpty(s) ? ""
              : s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;")
                 .Replace("\"", "&quot;").Replace("'", "&#39;");

        // Lazy-initialised, shared HttpClient — never per-call (socket exhaustion).
        private static readonly System.Lazy<HttpClient> s_httpClient =
            new(() => new HttpClient { Timeout = System.TimeSpan.FromSeconds(15) });
    }
}
