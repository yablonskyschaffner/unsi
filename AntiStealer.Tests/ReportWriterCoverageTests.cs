using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests;

/// <summary>
/// Section 6.9 — fills coverage gaps in <see cref="ReportWriter"/> /
/// <see cref="ReportWritersExtended"/>: empty batches, multi-result
/// batches, LOW/MEDIUM/HIGH sorting, special characters in fields,
/// determinism of GUIDs, and well-formedness across all writers.
/// </summary>
public class ReportWriterCoverageTests
{
    private static AnalysisResult Result(string path, int score, string family = "", string sha = "")
    {
        var r = new AnalysisResult(path)
        {
            FileType   = "pe",
            Sha256     = sha.Length > 0 ? sha : new string('a', 64),
            RiskScore  = score,
            FamilyName = family,
        };
        r.FinalizeFlags();
        return r;
    }

    // ------------------------------------------------------------------
    // Empty input — every writer must still produce a usable document.
    // ------------------------------------------------------------------

    [Fact]
    public void EmptyBatch_AllWritersProduceWellFormedOutput()
    {
        var empty = Array.Empty<AnalysisResult>();

        // JSON: schema + zero-length results array.
        using (var d = JsonDocument.Parse(ReportWriter.ToJson(empty)))
            Assert.Equal(0, d.RootElement.GetProperty("results").GetArrayLength());

        // CSV: header line only.
        var csv = ReportWriter.ToCsv(empty);
        Assert.StartsWith("File,Type,RiskScore", csv);
        Assert.Single(csv.Trim().Split('\n'));

        // HTML: still a valid document skeleton.
        var html = ReportWriter.ToHtml(empty);
        Assert.StartsWith("<!doctype html>", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("</html>", html);

        // PDF: header + EOF marker.
        var pdf = ReportWriter.ToPdfBytes(empty);
        Assert.StartsWith("%PDF", System.Text.Encoding.ASCII.GetString(pdf, 0, 4));

        // SARIF / STIX: valid JSON objects.
        using (var d = JsonDocument.Parse(ReportWriter.ToSarif(empty)))
            Assert.Equal("2.1.0", d.RootElement.GetProperty("version").GetString());
        using (var d = JsonDocument.Parse(ReportWriter.ToStix(empty)))
            Assert.Equal("bundle", d.RootElement.GetProperty("type").GetString());

        // MISP / OpenIOC / Markdown / CEF / Syslog: writers must not throw.
        Assert.False(string.IsNullOrEmpty(ReportWritersExtended.ToMispEvent(empty)));
        Assert.False(string.IsNullOrEmpty(ReportWritersExtended.ToOpenIoc(empty)));
        Assert.False(string.IsNullOrEmpty(ReportWritersExtended.ToMarkdown(empty)));
        // CEF on empty input produces an empty string (no rows) — that's fine.
        Assert.NotNull(ReportWritersExtended.ToCef(empty));
        Assert.NotNull(ReportWritersExtended.ToSyslogRfc5424(empty));
    }

    // ------------------------------------------------------------------
    // Multi-result batches — verify row counts and ordering.
    // ------------------------------------------------------------------

    [Fact]
    public void Multi_Csv_HasOneRowPerResult_PlusHeader()
    {
        var batch = new[]
        {
            Result("/a.exe", 15, "Lo"),
            Result("/b.exe", 45, "Md"),
            Result("/c.exe", 85, "Hi"),
        };
        var csv = ReportWriter.ToCsv(batch);
        var lines = csv.Trim().Split('\n');
        Assert.Equal(4, lines.Length);   // 1 header + 3 data
    }

    [Fact]
    public void Multi_Json_ResultsCountMatchesInput()
    {
        var batch = new[]
        {
            Result("/x", 10),
            Result("/y", 50),
            Result("/z", 90),
        };
        using var d = JsonDocument.Parse(ReportWriter.ToJson(batch));
        Assert.Equal(3, d.RootElement.GetProperty("results").GetArrayLength());
    }

    [Fact]
    public void Multi_Html_OrdersByRiskScoreDescending()
    {
        var batch = new[]
        {
            Result("/low.exe",    10, "L"),
            Result("/high.exe",   90, "H"),
            Result("/medium.exe", 50, "M"),
        };
        var html = ReportWriter.ToHtml(batch);
        int hi = html.IndexOf("high.exe",   StringComparison.Ordinal);
        int md = html.IndexOf("medium.exe", StringComparison.Ordinal);
        int lo = html.IndexOf("low.exe",    StringComparison.Ordinal);
        // First occurrence is the index row at the top of the document.
        Assert.True(hi < md, $"HIGH must appear before MEDIUM (got {hi} vs {md}).");
        Assert.True(md < lo, $"MEDIUM must appear before LOW (got {md} vs {lo}).");
    }

    // ------------------------------------------------------------------
    // SARIF severity levels — error / warning / note.
    // ------------------------------------------------------------------

    [Theory]
    [InlineData(85, "error")]
    [InlineData(50, "warning")]
    [InlineData(10, "note")]
    public void Sarif_LevelDerivedFromRiskScore(int score, string expectedLevel)
    {
        var r = Result("/sample.bin", score);
        var sarif = ReportWriter.ToSarif(new[] { r });
        using var d = JsonDocument.Parse(sarif);
        var lvl = d.RootElement
            .GetProperty("runs")[0]
            .GetProperty("results")[0]
            .GetProperty("level")
            .GetString();
        Assert.Equal(expectedLevel, lvl);
    }

    // ------------------------------------------------------------------
    // CSV escaping — embedded commas, quotes, newlines must be escaped.
    // ------------------------------------------------------------------

    [Fact]
    public void Csv_QuotesAndCommasInFieldsAreEscaped()
    {
        var r = new AnalysisResult("/path/with,comma.exe")
        {
            FileType   = "pe",
            Sha256     = new string('a', 64),
            FamilyName = "Family \"X\"",
            RiskScore  = 60,
        };
        r.FinalizeFlags();

        var csv = ReportWriter.ToCsv(new[] { r });
        var rows = csv.Trim().Split('\n');
        Assert.Equal(2, rows.Length); // header + one data row

        // Comma in file path forces quoting of that cell.
        Assert.Contains("\"/path/with,comma.exe\"", rows[1]);
        // Inner quotes are escaped as doubled quotes per RFC 4180.
        Assert.Contains("\"Family \"\"X\"\"\"", rows[1]);
    }

    // ------------------------------------------------------------------
    // HTML escaping — ampersand / < / > / quotes must be encoded.
    // ------------------------------------------------------------------

    [Fact]
    public void Html_EscapesSpecialCharactersInFields()
    {
        var r = new AnalysisResult("/tmp/<evil>.exe")
        {
            FileType   = "pe",
            Sha256     = new string('a', 64),
            FamilyName = "<script>alert('xss')</script>",
            RiskScore  = 95,
        };
        r.FinalizeFlags();

        var html = ReportWriter.ToHtml(new[] { r });
        // Raw `<script>` must NOT appear unescaped.
        Assert.DoesNotContain("<script>alert('xss')", html);
        // Standard HTML escaping replaces `<` with `&lt;` and `>` with `&gt;`.
        Assert.Contains("&lt;script&gt;", html);
    }

    // ------------------------------------------------------------------
    // STIX determinism — same input ⇒ same object IDs (deterministic GUID
    // helper). Different inputs ⇒ different IDs.
    // ------------------------------------------------------------------

    [Fact]
    public void Stix_DeterministicObjectIds_ForSameSha()
    {
        var a = Result("/a", 80);
        var b = Result("/a", 80);    // same path + same default sha
        var stixA = ReportWriter.ToStix(new[] { a });
        var stixB = ReportWriter.ToStix(new[] { b });

        // Bundle root carries a timestamp-derived id, so we strip it before
        // comparing — what we actually care about is that the per-object
        // file/malware ids are stable for the same SHA-256 input.
        static string ExtractFileId(string stix)
        {
            using var d = JsonDocument.Parse(stix);
            foreach (var o in d.RootElement.GetProperty("objects").EnumerateArray())
                if (o.GetProperty("type").GetString() == "file")
                    return o.GetProperty("id").GetString() ?? "";
            return "";
        }

        Assert.Equal(ExtractFileId(stixA), ExtractFileId(stixB));
    }

    [Fact]
    public void Stix_DifferentSha_YieldsDifferentFileId()
    {
        var a = Result("/a", 80, sha: new string('a', 64));
        var b = Result("/b", 80, sha: new string('b', 64));

        static string FileId(string stix)
        {
            using var d = JsonDocument.Parse(stix);
            foreach (var o in d.RootElement.GetProperty("objects").EnumerateArray())
                if (o.GetProperty("type").GetString() == "file")
                    return o.GetProperty("id").GetString() ?? "";
            return "";
        }

        Assert.NotEqual(FileId(ReportWriter.ToStix(new[] { a })),
                        FileId(ReportWriter.ToStix(new[] { b })));
    }

    // ------------------------------------------------------------------
    // PDF — non-ASCII characters must round-trip through the WinAnsi
    // transliteration step without throwing.
    // ------------------------------------------------------------------

    [Fact]
    public void Pdf_NonAsciiContentDoesNotThrow()
    {
        var r = new AnalysisResult("/tmp/файл.exe")
        {
            FileType   = "pe",
            Sha256     = new string('a', 64),
            FamilyName = "ロシア語 / 中文 / العربية",
            RiskScore  = 75,
        };
        r.StringHits.Add("漢字");
        r.FinalizeFlags();

        var pdf = ReportWriter.ToPdfBytes(new[] { r });
        Assert.True(pdf.Length > 256);
        Assert.StartsWith("%PDF", System.Text.Encoding.ASCII.GetString(pdf, 0, 4));
    }

    // ------------------------------------------------------------------
    // Diff writer — empty before/after = empty diff (no exceptions).
    // ------------------------------------------------------------------

    [Fact]
    public void Diff_EmptyBeforeAndAfter_NoFalseChanges()
    {
        var empty = ReportWriter.ToJson(Array.Empty<AnalysisResult>());
        var d = ReportWritersExtended.DiffJsonReports(empty, empty);
        Assert.Empty(d.AddedFiles);
        Assert.Empty(d.RemovedFiles);
        Assert.Empty(d.ChangedScore);
        Assert.Empty(d.ChangedLevel);
    }

    [Fact]
    public void Diff_DetectsRemovedFile()
    {
        var before = ReportWriter.ToJson(new[] { Result("/gone.exe", 80) });
        var after  = ReportWriter.ToJson(Array.Empty<AnalysisResult>());

        var d = ReportWritersExtended.DiffJsonReports(before, after);
        Assert.Contains(d.RemovedFiles, x => x.Contains("gone.exe"));
    }

    // ------------------------------------------------------------------
    // EE6 — completion scripts must be non-empty & contain command name.
    // ------------------------------------------------------------------

    [Fact]
    public void Completion_BashContainsCommandName()
    {
        var bash = ReportWritersExtended.ToBashCompletion();
        Assert.Contains("antistealer", bash, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Completion_ZshAndPowerShellAreNonEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(ReportWritersExtended.ToZshCompletion()));
        Assert.False(string.IsNullOrWhiteSpace(ReportWritersExtended.ToPowerShellCompletion()));
    }
}
