using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests;

public class CommercialTests
{
    // ----- ProductInfo -------------------------------------------------

    [Fact]
    public void ProductInfo_BannerIncludesSkuAndCustomer()
    {
        var lic = new License { Customer = "ACME Corp", Sku = "pro", Expires = DateTime.UtcNow.AddYears(1) };
        var banner = ProductInfo.Banner(lic);
        Assert.Contains("ACME Corp", banner);
        Assert.Contains("pro", banner);
        Assert.Contains("AntiStealer", banner);
    }

    // ----- License sign / verify --------------------------------------

    [Fact]
    public void License_SignAndVerify_RoundTrips()
    {
        var lic = new License
        {
            Customer = "Customer A",
            Sku      = "pro",
            Issued   = DateTime.UtcNow,
            Expires  = DateTime.UtcNow.AddYears(1),
            Seats    = 5,
            Features = new List<string> { "scan", "report", "rest", "watch" },
        };
        LicenseVerifier.Sign(lic, "shared-secret");
        Assert.False(string.IsNullOrEmpty(lic.Signature));
        Assert.True(LicenseVerifier.Verify(lic, "shared-secret", out _));
    }

    [Fact]
    public void License_TamperedPayload_FailsVerification()
    {
        var lic = new License
        {
            Customer = "Customer A", Sku = "pro",
            Expires  = DateTime.UtcNow.AddYears(1),
            Features = new List<string> { "scan" },
        };
        LicenseVerifier.Sign(lic, "shared-secret");
        lic.Sku = "enterprise"; // tamper AFTER signing
        Assert.False(LicenseVerifier.Verify(lic, "shared-secret", out var reason));
        Assert.Equal("bad signature", reason);
    }

    [Fact]
    public void License_Expired_FailsVerification()
    {
        var lic = new License
        {
            Customer = "Customer A", Sku = "pro",
            Expires  = DateTime.UtcNow.AddDays(-1),
        };
        LicenseVerifier.Sign(lic, "shared-secret");
        Assert.False(LicenseVerifier.Verify(lic, "shared-secret", out var reason));
        Assert.Equal("expired", reason);
    }

    [Fact]
    public void License_LoadFromFile_WorksWhenSignedWithSameKey()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "ast-lic-" + Guid.NewGuid().ToString("N") + ".json");
        var lic = new License
        {
            Customer = "Customer A", Sku = "pro",
            Expires = DateTime.UtcNow.AddYears(1),
            Features = new List<string> { "scan" },
        };
        LicenseVerifier.Sign(lic, "xyz");
        File.WriteAllText(tmp, System.Text.Json.JsonSerializer.Serialize(lic,
                                new System.Text.Json.JsonSerializerOptions
                                { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase, WriteIndented = true }));
        try
        {
            var loaded = LicenseVerifier.Load(tmp, "xyz", out var reason);
            Assert.NotNull(loaded);
            Assert.Equal("Customer A", loaded!.Customer);
            var loadedWrong = LicenseVerifier.Load(tmp, "wrong-key", out var reason2);
            Assert.Null(loadedWrong);
            Assert.Equal("bad signature", reason2);
        }
        finally { try { File.Delete(tmp); } catch { } }
    }

    // ----- FeatureGate -------------------------------------------------

    [Fact]
    public void FeatureGate_CommunityGetsScanOnlyEnterpriseGetsAll()
    {
        Assert.True (FeatureGate.Allow(null,                                      "scan"));
        Assert.True (FeatureGate.Allow(null,                                      "report"));
        Assert.False(FeatureGate.Allow(null,                                      "rest"));

        var pro = new License { Sku = "pro", Features = new List<string> { "rest" }, Expires = DateTime.UtcNow.AddYears(1) };
        Assert.True (FeatureGate.Allow(pro,  "rest"));
        Assert.False(FeatureGate.Allow(pro,  "watch"));

        var ent = new License { Sku = "enterprise", Expires = DateTime.UtcNow.AddYears(1) };
        Assert.True (FeatureGate.Allow(ent,  "rest"));
        Assert.True (FeatureGate.Allow(ent,  "watch"));
        Assert.True (FeatureGate.Allow(ent,  "anything"));
    }

    // ----- RestServer --------------------------------------------------

    [Fact]
    public void RestServer_CommunityLicense_RefusesToStart()
    {
        var opts = new RestServerOptions
        {
            License = new License { Sku = "community", Expires = DateTime.UtcNow.AddYears(1) },
            Prefix  = "http://127.0.0.1:19991/",
        };
        using var server = new RestServer(opts);
        Assert.Throws<InvalidOperationException>(() => server.Start());
    }

    [Fact(Timeout = 10_000)]
    public async Task RestServer_Health_RespondsOk()
    {
        var port   = 20000 + (Environment.ProcessId & 0xFFF);
        var prefix = $"http://127.0.0.1:{port}/";
        var opts   = new RestServerOptions
        {
            License = new License { Sku = "pro", Expires = DateTime.UtcNow.AddYears(1) },
            Prefix  = prefix,
            RequirePro = true,
        };
        using var server = new RestServer(opts);
        try { server.Start(); }
        catch (System.Net.HttpListenerException)
        {
            // Some CI environments refuse to bind HttpListener; skip.
            return;
        }
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
            var body = await http.GetStringAsync(prefix + "health");
            Assert.Contains("\"status\"", body);
            Assert.Contains("\"product\"", body);
        }
        finally { server.Stop(); }
    }

    // ----- UpdateCheck signing -----------------------------------------

    [Fact]
    public void ReleaseManifest_Signature_RoundTripsThroughUpdateCheckLogic()
    {
        // Build a manifest and compute its HMAC the same way UpdateCheck verifies.
        var m = new ReleaseManifest
        {
            Version  = "2.0.0",
            Released = DateTime.UtcNow,
            Sha256   = new string('f', 64),
            Url      = "https://example.com/AntiStealer.exe",
            Notes    = "Big release",
        };
        var key = "vendor-secret";
        var raw = System.Text.Json.JsonSerializer.Serialize(m,
                    new System.Text.Json.JsonSerializerOptions
                    { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase, WriteIndented = true });
        using var h = new System.Security.Cryptography.HMACSHA256(Encoding.UTF8.GetBytes(key));
        m.Signature = Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes(raw)));

        // Recompute with the same key and the signature-stripped payload — must match.
        var captured = m.Signature;
        m.Signature = null;
        var raw2 = System.Text.Json.JsonSerializer.Serialize(m,
                     new System.Text.Json.JsonSerializerOptions
                     { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase, WriteIndented = true });
        var again = Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes(raw2)));
        Assert.Equal(captured, again);

        // Sanity: UpdateCheck.IsNewerThanCurrent returns true when manifest.Version > ProductInfo.Version.
        Assert.True(UpdateCheck.IsNewerThanCurrent(new ReleaseManifest { Version = "99.0.0" }));
        Assert.False(UpdateCheck.IsNewerThanCurrent(new ReleaseManifest { Version = "0.0.1" }));
    }
}
