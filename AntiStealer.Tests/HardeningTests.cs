using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests;

// EncryptedQuarantine.QuarantineDir is a static; share an xUnit
// collection with CryptoUpgradeTests so they don't race on Windows
// where xUnit happily runs the two classes in parallel by default.
[Collection("EncryptedQuarantine")]
public class HardeningTests
{
    // ----- GG2: SafeExtract --------------------------------------------

    private static MemoryStream MakeZip(params (string name, byte[] data)[] entries)
    {
        var ms = new MemoryStream();
        using (var arch = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, data) in entries)
            {
                var e = arch.CreateEntry(name, CompressionLevel.NoCompression);
                using var s = e.Open();
                s.Write(data, 0, data.Length);
            }
        }
        ms.Position = 0;
        return ms;
    }

    [Fact]
    public void SafeExtract_RejectsPathTraversal()
    {
        using var zip = MakeZip(("../evil.exe", new byte[] { 1, 2, 3 }));
        var dest = Path.Combine(Path.GetTempPath(), "ast-gg2-" + Guid.NewGuid().ToString("N"));
        try
        {
            var r = SafeExtract.Zip(zip, dest);
            Assert.Equal(0, r.EntriesExtracted);
            Assert.Contains(r.Rejected, s => s.Contains("path-traversal"));
        }
        finally { try { Directory.Delete(dest, true); } catch { } }
    }

    [Fact]
    public void SafeExtract_EnforcesEntryCountCap()
    {
        var entries = new List<(string, byte[])>();
        for (int i = 0; i < 10; i++)
            entries.Add(($"f{i}.bin", new byte[] { 0 }));
        using var zip = MakeZip(entries.ToArray());
        var dest = Path.Combine(Path.GetTempPath(), "ast-gg2-" + Guid.NewGuid().ToString("N"));
        try
        {
            var r = SafeExtract.Zip(zip, dest, new SafeExtractOptions { MaxEntries = 3 });
            Assert.InRange(r.EntriesExtracted, 0, 3);
        }
        finally { try { Directory.Delete(dest, true); } catch { } }
    }

    // ----- GG3: SafeHttp -----------------------------------------------

    [Fact]
    public void SafeHttp_CreateClient_AppliesTimeoutAndUserAgent()
    {
        using var c = SafeHttp.CreateClient(new SafeHttpOptions
        {
            Timeout = TimeSpan.FromSeconds(3),
            UserAgent = "AntiStealer-test/1.0",
        });
        Assert.Equal(TimeSpan.FromSeconds(3), c.Timeout);
        Assert.Contains(c.DefaultRequestHeaders.UserAgent, h => h.Product?.Name == "AntiStealer-test");
    }

    // ----- GG5: AsiLogger ----------------------------------------------

    [Fact]
    public void AsiLogger_EmitsNdjsonToFile()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ast-gg5-" + Guid.NewGuid().ToString("N"));
        AsiLogger.LogDir = dir;
        try
        {
            AsiLogger.Info("scan started", new Dictionary<string, object?> { ["count"] = 3 });
            AsiLogger.Warn("unusual");
            AsiLogger.Error("broke");
            var path = Path.Combine(dir, DateTime.UtcNow.ToString("yyyy-MM-dd") + ".log");
            Assert.True(File.Exists(path));
            var lines = File.ReadAllLines(path);
            Assert.Equal(3, lines.Length);
            foreach (var l in lines)
            {
                Assert.StartsWith("{", l);
                Assert.Contains("\"ts\":", l);
                Assert.Contains("\"level\":", l);
            }
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    // ----- GG6: CrashReporter ------------------------------------------

    [Fact]
    public void CrashReporter_Write_WritesJsonWithStackAndSha()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ast-gg6-" + Guid.NewGuid().ToString("N"));
        CrashReporter.CrashDir = dir;
        CrashReporter.CurrentSampleSha256 = new string('d', 64);
        try
        {
            Exception? e = null;
            try { throw new InvalidOperationException("boom"); } catch (Exception ex) { e = ex; }
            CrashReporter.Write(e, "unit-test");
            var files = Directory.GetFiles(dir, "crash-*.json");
            Assert.NotEmpty(files);
            var text = File.ReadAllText(files[0]);
            Assert.Contains("\"source\": \"unit-test\"", text);
            Assert.Contains("boom", text);
            Assert.Contains(new string('d', 64), text);
        }
        finally
        {
            CrashReporter.CurrentSampleSha256 = null;
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    // ----- GG9: EncryptedQuarantine ------------------------------------

    [Fact]
    public void EncryptedQuarantine_RoundTripsPayload()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ast-gg9-" + Guid.NewGuid().ToString("N"));
        EncryptedQuarantine.QuarantineDir = dir;
        try
        {
            var src = Path.Combine(Path.GetTempPath(), "ast-gg9-in-" + Guid.NewGuid().ToString("N") + ".bin");
            var original = Encoding.UTF8.GetBytes("malicious content that must never run");
            File.WriteAllBytes(src, original);
            var sha = new string('e', 64);
            var rec = EncryptedQuarantine.Quarantine(src, sha);
            Assert.True(File.Exists(rec.StoredPath));
            var stored = File.ReadAllBytes(rec.StoredPath);
            Assert.NotEqual(original, stored);    // encrypted at rest
            var back = EncryptedQuarantine.Restore(sha);
            Assert.Equal(original, back);
            File.Delete(src);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }
}
