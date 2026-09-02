using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests;

// Section 11.5 — 11.11 — tests for the new report writers added in
// ReportsV2 plus the SARIF / STIX / PDF / HTML enrichments applied
// in PR 7. Each writer is exercised on an empty batch, a single
// HIGH-risk result, and a mixed-band batch.
public class ReportsV2Tests
{
    private static AnalysisResult Build(
        string path, int score, string family = "",
        string sha = "", string? type = "pe",
        IEnumerable<string>? urls = null,
        IEnumerable<string>? ipv4 = null,
        IEnumerable<string>? mitre = null)
    {
        var r = new AnalysisResult(path)
        {
            FileType   = type ?? "pe",
            Sha256     = !string.IsNullOrEmpty(sha) ? sha : new string('a', 64),
            RiskScore  = score,
            FamilyName = family,
        };
        if (urls is not null) foreach (var u in urls) r.UrlsFound.Add(u);
        if (ipv4 is not null) foreach (var i in ipv4) r.Ipv4Hits.Add(i);
        if (mitre is not null) foreach (var m in mitre) r.MitreTtps.Add(m);
        r.FinalizeFlags();
        return r;
    }

    // ──────────────────────────────────────────────────────────────────
    // 11.5 — XLSX
    // ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Xlsx_EmptyBatch_StillProducesValidWorkbook()
    {
        var bytes = ReportsV2.ToXlsx(Array.Empty<AnalysisResult>());
        Assert.True(bytes.Length > 256);
        // ZIP magic "PK\x03\x04".
        Assert.Equal(0x50, bytes[0]);
        Assert.Equal(0x4B, bytes[1]);
        using var ms  = new MemoryStream(bytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
        Assert.NotNull(zip.GetEntry("[Content_Types].xml"));
        Assert.NotNull(zip.GetEntry("xl/workbook.xml"));
        Assert.NotNull(zip.GetEntry("xl/worksheets/sheet1.xml"));
    }

    [Fact]
    public void Xlsx_RowsAndHeaderRender()
    {
        var batch = new[]
        {
            Build("/a.exe", 85, "Hi"),
            Build("/b.exe", 25, "Lo"),
        };
        var bytes = ReportsV2.ToXlsx(batch);
        using var ms  = new MemoryStream(bytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
        var sheet = zip.GetEntry("xl/worksheets/sheet1.xml")!;
        using var sr = new StreamReader(sheet.Open(), Encoding.UTF8);
        var xml = sr.ReadToEnd();

        // Header row + 2 data rows.
        Assert.Contains("<sheetData>", xml);
        Assert.Contains(">RiskScore<", xml);  // header cell
        Assert.Contains("/a.exe",       xml);
        Assert.Contains("/b.exe",       xml);
        Assert.Contains(">85<",         xml);
        Assert.Contains(">25<",         xml);
    }

    [Fact]
    public void Xlsx_SpecialCharsInFieldsAreXmlEscaped()
    {
        var r = new AnalysisResult("/p<>&\".exe")
        {
            FileType   = "pe",
            Sha256     = new string('a', 64),
            FamilyName = "<bad>&'\"",
            RiskScore  = 60,
        };
        r.FinalizeFlags();
        var bytes = ReportsV2.ToXlsx(new[] { r });
        using var zip = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);
        using var sr  = new StreamReader(zip.GetEntry("xl/worksheets/sheet1.xml")!.Open());
        var xml = sr.ReadToEnd();
        Assert.DoesNotContain("<bad>",   xml);   // not raw
        Assert.Contains("&lt;bad&gt;", xml);
    }

    // ──────────────────────────────────────────────────────────────────
    // 11.6 — ECS NDJSON
    // ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Ecs_OneLinePerResult_AndValidJsonObjects()
    {
        var batch = new[]
        {
            Build("/x.exe", 90, "Lumma"),
            Build("/y.exe", 30, "Generic"),
        };
        var text = ReportsV2.ToEcsNdjson(batch);
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);
        foreach (var line in lines)
        {
            using var doc = JsonDocument.Parse(line);
            // Mandatory ECS fields.
            Assert.True(doc.RootElement.TryGetProperty("@timestamp", out _));
            Assert.True(doc.RootElement.TryGetProperty("event",       out _));
            Assert.True(doc.RootElement.TryGetProperty("file",        out _));
            Assert.True(doc.RootElement.TryGetProperty("threat",      out _));
        }
    }

    [Fact]
    public void Ecs_EventSeverityMatchesRiskScore()
    {
        var r = Build("/x.exe", 95);
        var text = ReportsV2.ToEcsNdjson(new[] { r });
        using var doc = JsonDocument.Parse(text.Trim());
        int sev = doc.RootElement.GetProperty("event").GetProperty("severity").GetInt32();
        Assert.Equal(95, sev);
    }

    [Fact]
    public void Ecs_HashSha256FieldPopulated()
    {
        string sha = new string('b', 64);
        var r = Build("/a.exe", 80, sha: sha);
        var text = ReportsV2.ToEcsNdjson(new[] { r });
        using var doc = JsonDocument.Parse(text.Trim());
        var hashes = doc.RootElement.GetProperty("file").GetProperty("hash");
        Assert.Equal(sha, hashes.GetProperty("sha256").GetString());
    }

    // ──────────────────────────────────────────────────────────────────
    // 11.7 — Splunk HEC envelope
    // ──────────────────────────────────────────────────────────────────

    [Fact]
    public void SplunkHec_EnvelopeHasRequiredKeys()
    {
        var r = Build("/x.exe", 60);
        var text = ReportsV2.ToSplunkHec(new[] { r });
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Single(lines);
        using var doc = JsonDocument.Parse(lines[0]);
        foreach (var key in new[] { "time", "host", "source", "sourcetype", "index", "event" })
            Assert.True(doc.RootElement.TryGetProperty(key, out _),
                $"expected `{key}` in Splunk envelope; got: {lines[0]}");
        // event nested under HEC envelope must contain ECS shape.
        var ev = doc.RootElement.GetProperty("event");
        Assert.True(ev.TryGetProperty("@timestamp", out _));
    }

    [Fact]
    public async Task PushToSplunk_PostsAuthorizedJson()
    {
        var capture = new CapturingHandler(HttpStatusCode.OK);
        using var http = new HttpClient(capture);
        var r = Build("/x.exe", 80);
        var status = await ReportsV2.PushToSplunkAsync(
            "https://splunk.local:8088/services/collector", "tok-12345", new[] { r }, http);
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal(HttpMethod.Post, capture.LastRequest!.Method);
        Assert.Equal("Splunk",       capture.LastRequest.Headers.Authorization?.Scheme);
        Assert.Equal("tok-12345",    capture.LastRequest.Headers.Authorization?.Parameter);
        Assert.Contains("\"event\"", capture.LastBody);
    }

    // ──────────────────────────────────────────────────────────────────
    // 11.8 — Slack / Teams / Discord webhook payloads
    // ──────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("https://hooks.slack.com/services/T/B/X",  ReportsV2.WebhookKind.Slack)]
    [InlineData("https://contoso.webhook.office.com/abc",  ReportsV2.WebhookKind.Teams)]
    [InlineData("https://outlook.office.com/webhook/abc",  ReportsV2.WebhookKind.Teams)]
    [InlineData("https://discord.com/api/webhooks/1/abc",  ReportsV2.WebhookKind.Discord)]
    [InlineData("https://example.com/hook",                ReportsV2.WebhookKind.Generic)]
    public void Webhook_KindAutoDetect(string url, ReportsV2.WebhookKind expected)
    {
        Assert.Equal(expected, ReportsV2.DetectWebhookKind(url));
    }

    [Fact]
    public void Webhook_Slack_ContainsBlocksAndHeader()
    {
        var batch = new[] { Build("/a.exe", 90, "Lumma"), Build("/b.exe", 30) };
        var json  = ReportsV2.ToWebhookPayload(batch, ReportsV2.WebhookKind.Slack);
        using var doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("blocks", out var blocks));
        Assert.True(blocks.GetArrayLength() >= 2);
        Assert.Contains("HIGH",   json);
        Assert.Contains("AntiStealer", json);
    }

    [Fact]
    public void Webhook_Teams_IsMessageCard()
    {
        var json = ReportsV2.ToWebhookPayload(new[] { Build("/a.exe", 90) }, ReportsV2.WebhookKind.Teams);
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("MessageCard", doc.RootElement.GetProperty("@type").GetString());
        Assert.True(doc.RootElement.TryGetProperty("themeColor", out _));
        Assert.True(doc.RootElement.TryGetProperty("sections",   out _));
    }

    [Fact]
    public void Webhook_Discord_HasEmbedsArray()
    {
        var json = ReportsV2.ToWebhookPayload(new[] { Build("/a.exe", 90) }, ReportsV2.WebhookKind.Discord);
        using var doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("embeds", out var embeds));
        Assert.True(embeds.GetArrayLength() >= 1);
    }

    [Fact]
    public async Task PostToWebhook_DispatchesJsonAndReturnsStatus()
    {
        var capture = new CapturingHandler(HttpStatusCode.Created);
        using var http = new HttpClient(capture);
        var status = await ReportsV2.PostToWebhookAsync(
            "https://hooks.slack.com/services/T/B/X",
            new[] { Build("/x.exe", 90) }, http);
        Assert.Equal(HttpStatusCode.Created, status);
        Assert.Equal("application/json", capture.LastRequest!.Content!.Headers.ContentType?.MediaType);
    }

    // ──────────────────────────────────────────────────────────────────
    // 11.9 — Jira Cloud REST v3 issue payload
    // ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Jira_PayloadShape_IsAdfDoc()
    {
        var r    = Build("/c.exe", 80, "Lumma");
        var json = ReportsV2.ToJiraIssuePayload(r, "SEC");
        using var doc = JsonDocument.Parse(json);
        var fields = doc.RootElement.GetProperty("fields");
        Assert.Equal("SEC",         fields.GetProperty("project").GetProperty("key").GetString());
        Assert.Contains("AntiStealer", fields.GetProperty("summary").GetString());
        Assert.Equal("Highest",     fields.GetProperty("priority").GetProperty("name").GetString());
        Assert.Equal("doc",         fields.GetProperty("description").GetProperty("type").GetString());
        Assert.Equal(1,             fields.GetProperty("description").GetProperty("version").GetInt32());
        // Labels include risk band + family.
        var labels = fields.GetProperty("labels").EnumerateArray().Select(x => x.GetString()).ToArray();
        Assert.Contains("antistealer", labels);
        Assert.Contains("family-lumma", labels);
    }

    [Fact]
    public async Task PostToJira_UsesBasicAuth()
    {
        var capture = new CapturingHandler(HttpStatusCode.Created);
        using var http = new HttpClient(capture);
        var r = Build("/d.exe", 90);
        var status = await ReportsV2.PostToJiraAsync(
            "https://example.atlassian.net", "me@example.com", "tok-abc", r, "SEC", http);
        Assert.Equal(HttpStatusCode.Created, status);
        var auth = capture.LastRequest!.Headers.Authorization;
        Assert.Equal("Basic", auth?.Scheme);
        Assert.NotNull(auth?.Parameter);
        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(auth!.Parameter!));
        Assert.Equal("me@example.com:tok-abc", decoded);
        Assert.EndsWith("/rest/api/3/issue", capture.LastRequest.RequestUri!.AbsolutePath);
    }

    // ──────────────────────────────────────────────────────────────────
    // 11.10 — Suricata IDS rules
    // ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Suricata_GeneratesIpAndUrlRules_ForMediumOrHigher()
    {
        var r = Build("/x.exe", 80,
            urls: new[] { "https://evil.example.com/payload.exe" },
            ipv4: new[] { "1.2.3.4" });
        var text = ReportsV2.ToSuricataRules(new[] { r });
        Assert.Contains("alert ip any any -> 1.2.3.4 any", text);
        Assert.Contains("alert dns any any -> any any",    text);
        Assert.Contains("alert http any any -> any any",   text);
        Assert.Contains("evil.example.com",                text);
        Assert.Contains("sid:",                            text);
    }

    [Fact]
    public void Suricata_SkipsLowRisk()
    {
        var r = Build("/x.exe", 25, ipv4: new[] { "5.6.7.8" });
        var text = ReportsV2.ToSuricataRules(new[] { r });
        Assert.DoesNotContain("5.6.7.8", text);
    }

    [Fact]
    public void Suricata_StripsRuleTerminatorChars()
    {
        // Embedded `"`, `;` and `\` inside the URL would normally break
        // the surrounding `content:"…"` field; the writer must replace
        // them with `?` so the rule remains parseable.
        var r = Build("/x.exe", 80, urls: new[] { "https://e\"vil.example.com/a;b\\c.html" });
        var text = ReportsV2.ToSuricataRules(new[] { r });
        Assert.Contains("https://e?vil.example.com/a?b?c.html", text);
        // The original (un-sanitised) form must not appear anywhere.
        Assert.DoesNotContain("e\"vil",     text);
        Assert.DoesNotContain("a;b\\c.html", text);
        Assert.Contains("antistealer,risk HIGH", text);
    }

    // ──────────────────────────────────────────────────────────────────
    // 11.11 — Diff HTML
    // ──────────────────────────────────────────────────────────────────

    [Fact]
    public void DiffToHtml_RendersSectionsAndItems()
    {
        // DiffJsonReports groups by SHA-256, so give the two files
        // different hashes — otherwise they collapse onto a single
        // "score changed" row and never reach the added/removed buckets.
        var before = ReportWriter.ToJson(new[]
        {
            Build("/old.exe", 80, sha: new string('a', 64)),
        });
        var after  = ReportWriter.ToJson(new[]
        {
            Build("/new.exe", 85, sha: new string('b', 64)),
        });
        var d = ReportWritersExtended.DiffJsonReports(before, after);
        var html = ReportsV2.DiffToHtml(d);
        Assert.StartsWith("<!doctype html>", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("<title>AntiStealer diff</title>", html);
        Assert.Contains("Added files",   html);
        Assert.Contains("Removed files", html);
        Assert.Contains("new.exe",       html);
        Assert.Contains("old.exe",       html);
    }

    [Fact]
    public void DiffToHtml_EmptySummary_StillValidDocument()
    {
        var empty = ReportWriter.ToJson(Array.Empty<AnalysisResult>());
        var d = ReportWritersExtended.DiffJsonReports(empty, empty);
        var html = ReportsV2.DiffToHtml(d);
        Assert.Contains("No changes.", html);
        Assert.Contains("</html>",     html, StringComparison.OrdinalIgnoreCase);
    }

    // ──────────────────────────────────────────────────────────────────
    // 11.4 — Interactive HTML controls
    // ──────────────────────────────────────────────────────────────────

    [Fact]
    public void InteractiveHtml_HasFilterChips_SearchInput_AndScript()
    {
        var batch = new[]
        {
            Build("/a.exe", 90), Build("/b.exe", 50), Build("/c.exe", 10),
        };
        var html = ReportWriter.ToHtml(batch);
        Assert.Contains("class=\"chip\"",        html);
        Assert.Contains("data-level=\"HIGH\"",   html);
        Assert.Contains("data-level=\"MEDIUM\"", html);
        Assert.Contains("data-level=\"LOW\"",    html);
        Assert.Contains("id=\"q\"",              html);
        Assert.Contains("<script>",              html);
        Assert.Contains("prefers-color-scheme",  html);
    }

    // ──────────────────────────────────────────────────────────────────
    // ScanOutputWriter wiring for new formats.
    // ──────────────────────────────────────────────────────────────────

    [Fact]
    public void ScanOutputWriter_WritesXlsxToFile()
    {
        var tmp = Path.Combine(Path.GetTempPath(), $"as-{Guid.NewGuid():N}.xlsx");
        try
        {
            int rc = ScanOutputWriter.Write(
                new[] { Build("/x.exe", 90) }, "xlsx",
                tmp, batchDir: null, ndjson: false,
                stdout: TextWriter.Null, stderr: TextWriter.Null);
            Assert.Equal(CliExitCodes.Clean, rc);
            Assert.True(new FileInfo(tmp).Length > 256);
            using var zip = ZipFile.OpenRead(tmp);
            Assert.NotNull(zip.GetEntry("xl/workbook.xml"));
        }
        finally { try { File.Delete(tmp); } catch { } }
    }

    [Theory]
    [InlineData("ecs")]
    [InlineData("splunk-hec")]
    [InlineData("suricata")]
    [InlineData("slack")]
    [InlineData("teams")]
    [InlineData("discord")]
    public void ScanOutputWriter_WritesText_ForNewFormats(string fmt)
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        int rc = ScanOutputWriter.Write(
            new[] { Build("/x.exe", 80) }, fmt,
            outPath: null, batchDir: null, ndjson: false,
            stdout: stdout, stderr: stderr);
        Assert.Equal(CliExitCodes.Clean, rc);
        Assert.True(stdout.ToString().Length > 16);
    }

    [Fact]
    public void ScanOutputWriter_Jira_EmitsOneLinePerHighOrMediumResult()
    {
        var batch = new[]
        {
            Build("/h.exe", 90),
            Build("/m.exe", 60),
            Build("/l.exe", 20), // filtered (score < 40)
        };
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        int rc = ScanOutputWriter.Write(
            batch, "jira",
            outPath: null, batchDir: null, ndjson: false,
            stdout: stdout, stderr: stderr);
        Assert.Equal(CliExitCodes.Clean, rc);
        var lines = stdout.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);  // HIGH + MEDIUM only
    }

    [Fact]
    public void ScanOutputWriter_Xlsx_WithoutOut_ReturnsError()
    {
        var stderr = new StringWriter();
        int rc = ScanOutputWriter.Write(
            new[] { Build("/x.exe", 90) }, "xlsx",
            outPath: null, batchDir: null, ndjson: false,
            stdout: TextWriter.Null, stderr: stderr);
        Assert.Equal(CliExitCodes.Error, rc);
        Assert.Contains("--out", stderr.ToString());
    }

    // ──────────────────────────────────────────────────────────────────
    // Capturing HttpMessageHandler for the push helpers above.
    // ──────────────────────────────────────────────────────────────────
    private sealed class CapturingHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        public HttpRequestMessage? LastRequest { get; private set; }
        public string LastBody { get; private set; } = "";
        public CapturingHandler(HttpStatusCode status) => _status = status;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            if (request.Content is not null)
                LastBody = await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(_status);
        }
    }
}
