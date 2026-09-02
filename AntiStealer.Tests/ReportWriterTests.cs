using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests;

/// <summary>
/// I1: Unit tests for the ReportWriter export formats (E1–E6).
/// </summary>
public class ReportWriterTests
{
    private static AnalysisResult MakeResult()
    {
        var r = new AnalysisResult("C:\\samples\\foo.exe")
        {
            FileType = "pe",
            Sha256 = new string('a', 64),
            RiskScore = 82,
            FamilyName = "RedLine",
            FamilyConfidence = 87.5,
            IsSigned = false,
        };
        r.UrlsFound.Add("https://bad.example.invalid/beacon");
        r.Ipv4Hits.Add("203.0.113.99");
        r.SuspiciousApiHits.Add("CryptUnprotectData");
        r.CustomHeuristicHits.Add("B13:Login Data");
        r.FinalizeFlags();
        return r;
    }

    [Fact]
    public void ToJson_ProducesParsableJsonWithMetadata()
    {
        var json = ReportWriter.ToJson(new[] { MakeResult() });
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("schema", out _));
        Assert.True(root.TryGetProperty("generated_at", out _));
        Assert.True(root.TryGetProperty("tool", out var tool));
        Assert.Equal("AntiStealer", tool.GetProperty("name").GetString());
        Assert.True(root.TryGetProperty("results", out var results));
        Assert.Equal(1, results.GetArrayLength());
    }

    [Fact]
    public void ToHtml_ContainsRiskLevelAndFileName()
    {
        var html = ReportWriter.ToHtml(new[] { MakeResult() });
        Assert.Contains("<html", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("foo.exe", html);
        Assert.Contains("RedLine", html);
    }

    [Fact]
    public void ToCsv_HasHeaderAndOneDataRow()
    {
        var csv = ReportWriter.ToCsv(new[] { MakeResult() });
        var lines = csv.Trim().Split('\n');
        Assert.True(lines.Length >= 2, "CSV must have header + at least one data row.");
        Assert.Contains("File,Type,RiskScore", lines[0]);
        Assert.Contains("RedLine", lines[1]);
    }

    [Fact]
    public void ToPdfBytes_StartsWithPdfMagic()
    {
        var bytes = ReportWriter.ToPdfBytes(new[] { MakeResult() });
        Assert.True(bytes.Length > 100, "PDF should be non-trivial in size.");
        Assert.Equal((byte)'%', bytes[0]);
        Assert.Equal((byte)'P', bytes[1]);
        Assert.Equal((byte)'D', bytes[2]);
        Assert.Equal((byte)'F', bytes[3]);
    }

    [Fact]
    public void ToStix_IsValidJsonBundleWithFileAndMalwareObjects()
    {
        var stix = ReportWriter.ToStix(new[] { MakeResult() });
        using var doc = JsonDocument.Parse(stix);
        var root = doc.RootElement;
        Assert.Equal("bundle", root.GetProperty("type").GetString());
        Assert.True(root.TryGetProperty("objects", out var objects));
        bool hasFile = false, hasMalware = false;
        foreach (var o in objects.EnumerateArray())
        {
            var t = o.GetProperty("type").GetString();
            if (t == "file") hasFile = true;
            if (t == "malware") hasMalware = true;
        }
        Assert.True(hasFile);
        Assert.True(hasMalware);
    }

    [Fact]
    public void ToSarif_HasRunsAndResults()
    {
        var sarif = ReportWriter.ToSarif(new[] { MakeResult() });
        using var doc = JsonDocument.Parse(sarif);
        var root = doc.RootElement;
        Assert.Equal("2.1.0", root.GetProperty("version").GetString());
        Assert.True(root.TryGetProperty("runs", out var runs));
        Assert.Equal(1, runs.GetArrayLength());
        Assert.True(runs[0].TryGetProperty("results", out var results));
        Assert.True(results.GetArrayLength() >= 1);
    }

    // ----- EE1-EE7 additional writers ----------------------------------

    [Fact]
    public void ToMispEvent_ContainsEventWithAttributes()
    {
        var misp = ReportWritersExtended.ToMispEvent(new[] { MakeResult() });
        using var doc = JsonDocument.Parse(misp);
        Assert.True(doc.RootElement.TryGetProperty("Event", out var evt));
        Assert.True(evt.TryGetProperty("Attribute", out var attrs));
        Assert.True(attrs.GetArrayLength() >= 3);
    }

    [Fact]
    public void ToOpenIoc_IsValidXmlWithIndicatorItems()
    {
        var xml = ReportWritersExtended.ToOpenIoc(new[] { MakeResult() });
        Assert.Contains("<ioc xmlns=\"http://schemas.mandiant.com/2010/ioc\"", xml);
        Assert.Contains("<IndicatorItem", xml);
        Assert.Contains(new string('a', 64), xml);
    }

    [Fact]
    public void ToMarkdown_HasHeaderRowAndFileSection()
    {
        var md = ReportWritersExtended.ToMarkdown(new[] { MakeResult() });
        Assert.Contains("# AntiStealer report", md);
        Assert.Contains("| File | Type | Score |", md);
        Assert.Contains("RedLine", md);
    }

    [Fact]
    public void ToCef_HasCefHeaderAndFields()
    {
        var cef = ReportWritersExtended.ToCef(new[] { MakeResult() });
        Assert.StartsWith("CEF:0|AntiStealer|AntiStealer|", cef);
        Assert.Contains("fileHash=", cef);
        Assert.Contains("cs1Label=RiskScore", cef);
    }

    [Fact]
    public void ToSyslog_WrapsCefLineWithRfc5424Header()
    {
        var syslog = ReportWritersExtended.ToSyslogRfc5424(new[] { MakeResult() }, host: "test-host");
        Assert.Contains("<108>1 ", syslog);
        Assert.Contains("test-host antistealer", syslog);
        Assert.Contains("CEF:0|", syslog);
    }

    [Fact]
    public void DiffJsonReports_DetectsAddedAndChangedFiles()
    {
        // "before" run has just foo.exe at score 36 (MEDIUM level derived on FinalizeFlags)
        var before = new AnalysisResult("foo.exe") { Sha256 = new string('a', 64), RiskScore = 36 };
        before.UrlsFound.Add("https://old.invalid/a");
        before.FinalizeFlags();
        // "after" adds a new file and escalates foo.exe to HIGH (100)
        var afterFoo = new AnalysisResult("foo.exe") { Sha256 = new string('a', 64), RiskScore = 100 };
        afterFoo.UrlsFound.Add("https://old.invalid/a");
        afterFoo.UrlsFound.Add("https://new.invalid/b");
        afterFoo.MitreTtps.Add("T1555.003");
        afterFoo.FinalizeFlags();
        var afterBar = new AnalysisResult("bar.js") { Sha256 = new string('b', 64), RiskScore = 95 };
        afterBar.FinalizeFlags();

        var oldJson = ReportWriter.ToJson(new[] { before });
        var newJson = ReportWriter.ToJson(new[] { afterFoo, afterBar });

        var d = ReportWritersExtended.DiffJsonReports(oldJson, newJson);
        Assert.Contains(d.AddedFiles,   x => x.Contains("bar.js"));
        Assert.Contains(d.ChangedScore, x => x.Contains("36 → 100"));
        Assert.Contains(d.ChangedLevel, x => x.Contains("→ HIGH"));
        Assert.Contains(d.NewUrls,      x => x.Contains("new.invalid"));
        Assert.Contains(d.NewTtps,      x => x.Contains("T1555.003"));

        var md = ReportWritersExtended.DiffToMarkdown(d);
        Assert.Contains("Added files", md);
        Assert.Contains("Changed score", md);
    }
}
