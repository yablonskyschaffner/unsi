using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests;

/// <summary>
/// Section 6.2 — snapshot tests for the serialization formats produced by
/// <see cref="ReportWriter"/> and <see cref="ReportWritersExtended"/>.
///
/// Pure binary golden-file diffs would be brittle (timestamps, GUIDs,
/// dictionary iteration order…), so each snapshot here is a **shape
/// assertion**: a deterministic <see cref="AnalysisResult"/> is fed through
/// the writer and the result is then parsed and compared against an
/// expected structural fingerprint (top-level keys, counts, magic numbers,
/// schema versions). The fingerprint is intentionally narrow so detector
/// changes that don't alter the report schema don't churn the goldens, but
/// any schema regression (renamed key, dropped field, version bump) trips
/// the test.
/// </summary>
public class SnapshotTests
{
    /// <summary>Build a deterministic <see cref="AnalysisResult"/> with
    /// every interesting hit list populated, then run
    /// <see cref="AnalysisResult.FinalizeFlags"/>. All values are static so
    /// the snapshot doesn't drift on every run.</summary>
    private static AnalysisResult Sample()
    {
        var r = new AnalysisResult("/tmp/sample.exe")
        {
            FileType = "pe",
            Size = 65_536,
            Sha256 = new string('a', 64),
            ImpHash = "112233445566778899aabbccddeeff00",
            FuzzyHash = "abcd:efgh",
            IsSigned = false,
            IsDotNetLikely = true,
            Is64 = true,
            IsDll = false,
            IsExe = true,
            RiskScore = 87,
            FamilyName = "RedLine",
            FamilyConfidence = 92.5,
            FamilyReason = "string-fingerprint",
        };
        r.UrlsFound.Add("https://bad.example.invalid/beacon");
        r.UrlsFound.Add("https://bad.example.invalid/exfil");
        r.Ipv4Hits.Add("203.0.113.99");
        r.Ipv4Hits.Add("198.51.100.42");
        r.EmailHits.Add("op@bad.example.invalid");
        r.JwtHits.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.signaturepartdummy");
        r.TelegramBotTokenHits.Add("123456:AAFakeBotTokenAAFakeBotTokenAAFake1");
        r.DiscordTokenHits.Add(new string('M', 24) + "." + new string('A', 6) + "." + new string('Z', 27));
        r.CryptoWalletHits.Add("BTC:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        r.CryptoWalletHits.Add("ETH:0x52908400098527886E0F7030069857D2E4169EE7");
        r.SuspiciousApiHits.Add("CryptUnprotectData");
        r.SuspiciousApiHits.Add("WinHttpSendRequest");
        r.NetDllHits.Add("WININET.DLL");
        r.CustomHeuristicHits.Add("B13:Login Data");
        r.StringHits.Add("encrypted_key");
        r.MalwareSelfIdHits.Add("RedLineStealer");
        r.GameTargetHits.Add("steam");
        r.MitreTtps.Add("T1555.003");
        r.MitreTtps.Add("T1041");
        r.ExternalRuleHits.Add("yara:RedLineGeneric (+5)");
        r.PrivateKeyBlockHits = 1;
        r.Base64BlobHits = 3;
        r.FinalizeFlags();
        return r;
    }

    // ------------------------------------------------------------------
    // JSON snapshot
    // ------------------------------------------------------------------

    [Fact]
    public void Snapshot_Json_Schema_And_KeyShape()
    {
        var json = ReportWriter.ToJson(new[] { Sample() });
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        // Top-level keys & schema URI are part of the public contract.
        Assert.Equal("https://whysgit.github.io/antistealer/report.v1.json",
                     root.GetProperty("schema").GetString());
        Assert.Equal("AntiStealer", root.GetProperty("tool").GetProperty("name").GetString());
        Assert.Equal("1.0",         root.GetProperty("tool").GetProperty("version").GetString());

        // Timestamp must be ISO 8601, but we don't pin the value.
        var ts = root.GetProperty("generated_at").GetString();
        Assert.NotNull(ts);
        Assert.True(DateTimeOffset.TryParse(ts, out _), $"generated_at must parse as ISO 8601, got '{ts}'.");

        var results = root.GetProperty("results");
        Assert.Equal(1, results.GetArrayLength());

        var r0 = results[0];
        var expectedKeys = new[]
        {
            "FilePath", "FileType", "Size", "Sha256", "ImpHash",
            "RiskScore", "FamilyName", "FamilyConfidence",
            "UrlsFound", "Ipv4Hits", "EmailHits", "JwtHits",
            "TelegramBotTokenHits", "DiscordTokenHits", "CryptoWalletHits",
            "SuspiciousApiHits", "MitreTtps", "ExternalRuleHits",
            "RiskLevel", "ReasonsShort",
        };
        var actualKeys = r0.EnumerateObject().Select(p => p.Name).ToHashSet();
        foreach (var k in expectedKeys)
            Assert.True(actualKeys.Contains(k), $"JSON snapshot missing key '{k}'. Got: [{string.Join(",", actualKeys.OrderBy(x => x))}]");

        // Spot-check a few values for byte-for-byte stability.
        Assert.Equal("HIGH",                                 r0.GetProperty("RiskLevel").GetString());
        Assert.Equal(87,                                     r0.GetProperty("RiskScore").GetInt32());
        Assert.Equal(new string('a', 64),                    r0.GetProperty("Sha256").GetString());
        Assert.Equal(2,                                      r0.GetProperty("UrlsFound").GetArrayLength());
        Assert.Equal(2,                                      r0.GetProperty("Ipv4Hits").GetArrayLength());
        Assert.Equal("RedLine",                              r0.GetProperty("FamilyName").GetString());
    }

    // ------------------------------------------------------------------
    // SARIF 2.1.0 snapshot
    // ------------------------------------------------------------------

    [Fact]
    public void Snapshot_Sarif_Version_Tool_Result_Shape()
    {
        var sarif = ReportWriter.ToSarif(new[] { Sample() });
        using var doc = JsonDocument.Parse(sarif);
        var root = doc.RootElement;

        Assert.Equal("2.1.0",     root.GetProperty("version").GetString());
        // SARIF writer emits `schema` (not `$schema`) — matches the public contract today.
        Assert.StartsWith("http", root.GetProperty("schema").GetString());

        var runs = root.GetProperty("runs");
        Assert.Equal(1, runs.GetArrayLength());

        var run = runs[0];
        var tool = run.GetProperty("tool").GetProperty("driver");
        Assert.Equal("AntiStealer", tool.GetProperty("name").GetString());
        Assert.NotNull(tool.GetProperty("informationUri").GetString());

        var results = run.GetProperty("results");
        Assert.True(results.GetArrayLength() >= 1);
        var res0 = results[0];
        Assert.True(res0.TryGetProperty("ruleId",  out _));
        Assert.True(res0.TryGetProperty("level",   out _));
        Assert.True(res0.TryGetProperty("message", out _));
        Assert.True(res0.TryGetProperty("locations", out var locs));
        Assert.True(locs.GetArrayLength() >= 1);

        // For RiskScore=87 (HIGH) we expect SARIF level "error".
        Assert.Equal("error", res0.GetProperty("level").GetString());
    }

    // ------------------------------------------------------------------
    // STIX 2.1 snapshot
    // ------------------------------------------------------------------

    [Fact]
    public void Snapshot_Stix_Bundle_With_File_And_Malware_Objects()
    {
        var stix = ReportWriter.ToStix(new[] { Sample() });
        using var doc = JsonDocument.Parse(stix);
        var root = doc.RootElement;

        Assert.Equal("bundle", root.GetProperty("type").GetString());
        Assert.Matches("^bundle--", root.GetProperty("id").GetString() ?? "");
        var objects = root.GetProperty("objects");
        Assert.True(objects.GetArrayLength() >= 2);

        var types = new HashSet<string>(StringComparer.Ordinal);
        foreach (var o in objects.EnumerateArray())
            types.Add(o.GetProperty("type").GetString() ?? "");

        Assert.Contains("file", types);
        Assert.Contains("malware", types);

        // Every STIX object must carry an `id` of the form `<type>--<uuid>`.
        foreach (var o in objects.EnumerateArray())
        {
            var t  = o.GetProperty("type").GetString();
            var id = o.GetProperty("id").GetString();
            Assert.Matches($"^{t}--", id ?? "");
        }
    }

    // ------------------------------------------------------------------
    // CSV snapshot
    // ------------------------------------------------------------------

    [Fact]
    public void Snapshot_Csv_Header_And_Single_Row()
    {
        var csv = ReportWriter.ToCsv(new[] { Sample() });
        var lines = csv.TrimEnd().Split('\n');
        Assert.Equal(2, lines.Length); // header + one row

        // Header is part of the public contract.
        Assert.Equal(
            "File,Type,RiskScore,RiskLevel,Family,Confidence,Net,Packed,Signed,Heuristics,URLs,API,IOCs,SHA256,Reasons",
            lines[0].TrimEnd('\r'));

        // The data row must contain known values from Sample().
        var row = lines[1];
        Assert.Contains("/tmp/sample.exe", row);
        Assert.Contains("pe",              row);
        Assert.Contains("87",              row);
        Assert.Contains("HIGH",            row);
        Assert.Contains("RedLine",         row);
        Assert.Contains(new string('a', 64), row);
    }

    // ------------------------------------------------------------------
    // HTML snapshot — just verify structural fragments.
    // ------------------------------------------------------------------

    [Fact]
    public void Snapshot_Html_Document_Skeleton()
    {
        var html = ReportWriter.ToHtml(new[] { Sample() });
        Assert.StartsWith("<!doctype html>", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("<title>AntiStealer report</title>",            html);
        Assert.Contains("<table>",                                       html);
        Assert.Contains("<thead>",                                       html);
        Assert.Contains("<tbody>",                                       html);
        Assert.Contains("class=\"risk-high\"",                           html); // sample is HIGH
        Assert.Contains("sample.exe",                                    html);
        Assert.Contains("RedLine",                                       html);
        Assert.Contains("</html>",                                       html);
    }

    // ------------------------------------------------------------------
    // PDF snapshot — non-trivial header bytes & EOF marker.
    // ------------------------------------------------------------------

    [Fact]
    public void Snapshot_Pdf_Header_And_Eof_Marker()
    {
        var bytes = ReportWriter.ToPdfBytes(new[] { Sample() });
        Assert.True(bytes.Length > 256, $"PDF should be > 256 bytes, got {bytes.Length}.");
        Assert.Equal((byte)'%', bytes[0]);
        Assert.Equal((byte)'P', bytes[1]);
        Assert.Equal((byte)'D', bytes[2]);
        Assert.Equal((byte)'F', bytes[3]);
        Assert.Equal((byte)'-', bytes[4]);

        // PDF must end with %%EOF (with optional trailing newline).
        var tail = System.Text.Encoding.ASCII.GetString(
            bytes, Math.Max(0, bytes.Length - 32), Math.Min(32, bytes.Length));
        Assert.Contains("%%EOF", tail);
    }

    // ------------------------------------------------------------------
    // MISP snapshot
    // ------------------------------------------------------------------

    [Fact]
    public void Snapshot_Misp_Event_Wrapper_Shape()
    {
        var misp = ReportWritersExtended.ToMispEvent(new[] { Sample() });
        using var doc = JsonDocument.Parse(misp);
        var evt = doc.RootElement.GetProperty("Event");

        Assert.False(evt.GetProperty("published").GetBoolean());
        Assert.Equal(2, evt.GetProperty("threat_level_id").GetInt32());

        var attrs = evt.GetProperty("Attribute");
        Assert.True(attrs.GetArrayLength() >= 5, $"Expected ≥5 attributes, got {attrs.GetArrayLength()}.");

        var firstAttr = attrs[0];
        Assert.True(firstAttr.TryGetProperty("type", out _));
        Assert.True(firstAttr.TryGetProperty("category", out _));
        Assert.True(firstAttr.TryGetProperty("value", out _));
        Assert.True(firstAttr.TryGetProperty("uuid", out _));
    }

    // ------------------------------------------------------------------
    // OpenIOC snapshot — namespace, ID format, indicator items.
    // ------------------------------------------------------------------

    [Fact]
    public void Snapshot_OpenIoc_NamespaceAndIndicatorItems()
    {
        var xml = ReportWritersExtended.ToOpenIoc(new[] { Sample() });
        Assert.Contains("<ioc xmlns=\"http://schemas.mandiant.com/2010/ioc\"",          xml);
        Assert.Contains("<short_description>AntiStealer IOC export</short_description>", xml);
        Assert.Contains("<description>AntiStealer IOC set</description>",                xml);
        Assert.Contains("<IndicatorItem",                                                xml);
        // Must reference our sample SHA-256 verbatim.
        Assert.Contains(new string('a', 64),                                         xml);
    }

    // ------------------------------------------------------------------
    // Markdown snapshot
    // ------------------------------------------------------------------

    [Fact]
    public void Snapshot_Markdown_Headings_And_TableHeader()
    {
        var md = ReportWritersExtended.ToMarkdown(new[] { Sample() });
        Assert.Contains("# AntiStealer report",      md);
        Assert.Contains("| File | Type | Score |",    md);
        Assert.Contains("|------|------|-------|",    md);
        Assert.Contains("sample.exe",              md);
        Assert.Contains("RedLine",                 md);
        Assert.Contains("HIGH",                    md);
    }

    // ------------------------------------------------------------------
    // CEF & syslog snapshots
    // ------------------------------------------------------------------

    [Fact]
    public void Snapshot_Cef_Header_And_KnownFields()
    {
        var cef = ReportWritersExtended.ToCef(new[] { Sample() });
        // CEF header (version|vendor|product|product-version|signature|name|severity)
        Assert.StartsWith("CEF:0|AntiStealer|AntiStealer|", cef);
        Assert.Contains("|HIGH|",     cef);
        Assert.Contains("fileHash=",  cef);
        Assert.Contains("cs1Label=RiskScore", cef);
        Assert.Contains("cs1=87",     cef);
    }

    [Fact]
    public void Snapshot_Syslog_Rfc5424_Header_Wraps_Cef()
    {
        var sys = ReportWritersExtended.ToSyslogRfc5424(new[] { Sample() }, host: "snap-host");
        // Should start with <PRI>1 …
        Assert.Matches(new Regex(@"^<\d+>1 "), sys);
        Assert.Contains("snap-host antistealer", sys);
        Assert.Contains("CEF:0|",                sys);
    }

    // ------------------------------------------------------------------
    // ToFullReport snapshot — sanity check on the human-readable
    // pretty-printed report. We verify section markers are present.
    // ------------------------------------------------------------------

    [Fact]
    public void Snapshot_FullReport_ContainsCanonicalSectionMarkers()
    {
        var text = Sample().ToFullReport();
        Assert.Contains("File: /tmp/sample.exe", text);
        Assert.Contains("Type: pe",              text);
        Assert.Contains("SHA256:",               text);
        Assert.Contains("Signed:",               text);
        Assert.Contains("HIGH",                  text);
        Assert.Contains("RedLine",               text);
    }
}
