using System.Linq;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests
{
    public class FamilyDetectorsTests
    {
        private static AnalysisResult Make(params string[] strings)
        {
            var r = new AnalysisResult("x") { FileType = "PE" };
            r.StringHits.AddRange(strings);
            return r;
        }

        // ------------------------------------------------------------------
        // 2.1 — stealer families
        // ------------------------------------------------------------------

        [Fact]
        public void Stealer_Rhadamanthys_HighConfidence()
        {
            var r = Make("rhadamanthys build 0.5.0", "exfil to 1.2.3.4:80");
            var m = StealerFamilyDetector.Detect(r);
            Assert.NotNull(m);
            Assert.Equal("Rhadamanthys", m!.Family);
            Assert.True(m.Confidence >= 90);
        }

        [Fact]
        public void Stealer_AtomicAmos_FromExplicitMarker()
        {
            var r = Make("atomicstealer ready", "send to https://amos.exfil");
            var m = StealerFamilyDetector.Detect(r);
            Assert.NotNull(m);
            Assert.Equal("Atomic", m!.Family);
        }

        [Fact]
        public void Stealer_Banshee_FromString()
        {
            var r = Make("banshee_stealer payload");
            var m = StealerFamilyDetector.Detect(r);
            Assert.NotNull(m);
            Assert.Equal("Banshee", m!.Family);
        }

        [Fact]
        public void Stealer_Stealc_FromMarker()
        {
            var r = Make("stealc v1.0.0", "decrypt browser passwords");
            var m = StealerFamilyDetector.Detect(r);
            Assert.NotNull(m);
            Assert.Equal("Stealc", m!.Family);
        }

        [Fact]
        public void Stealer_Phemedrone_AndWhiteSnake_AndMystic_AndAurora_FromMarkers()
        {
            Assert.Equal("Phemedrone", StealerFamilyDetector.Detect(Make("phemedrone client init"))!.Family);
            Assert.Equal("WhiteSnake", StealerFamilyDetector.Detect(Make("whitesnake build 4.7"))!.Family);
            Assert.Equal("Mystic",     StealerFamilyDetector.Detect(Make("mysticstealer rust core"))!.Family);
            Assert.Equal("Aurora",     StealerFamilyDetector.Detect(Make("auroralogger init"))!.Family);
        }

        [Fact]
        public void Stealer_DcRat_FromBuilderMarker()
        {
            var m = StealerFamilyDetector.Detect(Make("dcratbuilder.dll loaded"));
            Assert.NotNull(m);
            Assert.Equal("DCRat", m!.Family);
        }

        [Fact]
        public void Stealer_AmosBehaviouralFallback_FromKeychainExfil()
        {
            // No explicit "atomicstealer" string — should still trip the
            // Atomic behavioural rule via keychain+chrome markers.
            var r = Make(
                "Application Support/Google/Chrome/Default",
                "login.keychain-db read",
                "exfil request");
            var m = StealerFamilyDetector.Detect(r);
            Assert.NotNull(m);
            Assert.Equal("Atomic", m!.Family);
        }

        [Fact]
        public void Stealer_Returns_Null_When_NoMatch()
        {
            var m = StealerFamilyDetector.Detect(Make("hello world", "boring strings"));
            Assert.Null(m);
        }

        // ------------------------------------------------------------------
        // 2.2 — loaders
        // ------------------------------------------------------------------

        [Theory]
        [InlineData("smokeloader",   "SmokeLoader")]
        [InlineData("guloader",      "GuLoader")]
        [InlineData("privateloader", "PrivateLoader")]
        [InlineData("amadey",        "Amadey")]
        [InlineData("darkgate",      "DarkGate")]
        [InlineData("bumblebee",     "BumbleBee")]
        [InlineData("icedid",        "IcedID")]
        [InlineData("pikabot",       "Pikabot")]
        [InlineData("socgholish",    "SocGholish")]
        public void Loader_Markers_Detected(string marker, string family)
        {
            var m = LoaderFamilyDetector.Detect(Make(marker + " init"));
            Assert.NotNull(m);
            Assert.Equal(family, m!.Family);
        }

        [Fact]
        public void Loader_NetSupport_FromClientBinary()
        {
            var m = LoaderFamilyDetector.Detect(Make("client32.exe sideload"));
            Assert.NotNull(m);
            Assert.Equal("NetSupport", m!.Family);
        }

        // ------------------------------------------------------------------
        // 2.3 — cloud-credential detector
        // ------------------------------------------------------------------

        [Fact]
        public void Cloud_AwsAccessKey_IsCaught()
        {
            var r = Make("AWS_ACCESS_KEY_ID=FAKEFAKEFAKE");
            var hits = CloudConfigDetector.Detect(r);
            Assert.Contains("aws:access_key", hits);
        }

        [Fact]
        public void Cloud_AwsSecret_IsCaught()
        {
            var r = Make("aws_secret=FAKEFAKEFAKE");
            var hits = CloudConfigDetector.Detect(r);
            Assert.Contains("aws:secret_key", hits);
        }

        [Fact]
        public void Cloud_AzureConn_Sas_Are_Caught()
        {
            var r = Make(
                "DefaultEndpointsProtocol=https;AccountName=acme;AccountKey=" + new string('A', 60),
                "https://acme.blob.core.windows.net/x?sv=2022-05-04&ss=b&srt=co&sp=rwdlacx&sig=AbCdEf%2F12345");
            var hits = CloudConfigDetector.Detect(r);
            Assert.Contains("azure:connection_string", hits);
            Assert.Contains("azure:sas_token", hits);
            Assert.Contains("azure:storage_account", hits);
        }

        [Fact]
        public void Cloud_GcpServiceAccount_IsCaught()
        {
            var r = Make("{\"type\": \"service_account\",\"project_id\":\"x\"}");
            var hits = CloudConfigDetector.Detect(r);
            Assert.Contains("gcp:service_account", hits);
        }

        [Fact]
        public void Cloud_Webhooks_Slack_Discord_Teams_Detected()
        {
            var r = Make(
                "https://hooks.slack.com/services/FAKEFAKEFAKE",
                "https://discord.com/api/webhooks/FAKEFAKEFAKE",
                "https://acme.webhook.office.com/webhookb2/FAKEFAKEFAKE");
            var hits = CloudConfigDetector.Detect(r);
            Assert.Contains("slack:webhook",   hits);
            Assert.Contains("discord:webhook", hits);
            Assert.Contains("teams:webhook",   hits);
        }

        [Fact]
        public void Cloud_Sendgrid_Mailgun_IsCaught()
        {
            var r = Make(
                "SG.abcdefghijklmnopqrstuv.0123456789abcdefghijklmnopqrstuvwxyz_-ABCDE",
                "key-0123456789abcdef0123456789abcdef");
            var hits = CloudConfigDetector.Detect(r);
            Assert.Contains("sendgrid:api_key", hits);
            Assert.Contains("mailgun:api_key",  hits);
        }

        [Fact]
        public void Cloud_TelegramBotToken_FromExistingHits()
        {
            var r = Make("regular strings");
            r.TelegramBotTokenHits.Add("1234567890:ABC-def");
            var hits = CloudConfigDetector.Detect(r);
            Assert.Contains("telegram:bot_token", hits);
        }

        [Fact]
        public void Cloud_NoHits_OnCleanSample()
        {
            var r = Make("this binary contains nothing of interest", "hello world");
            var hits = CloudConfigDetector.Detect(r);
            Assert.Empty(hits);
        }

        // ------------------------------------------------------------------
        // Pipeline glue
        // ------------------------------------------------------------------

        [Fact]
        public void Pipeline_RunsAllThree_OnSingleSample()
        {
            var r = Make(
                "rhadamanthys build 0.5",
                "smokeloader init",
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
            FamilyDetectorPipeline.RunOn(r);
            Assert.Equal("Rhadamanthys", r.FamilyName);
            Assert.Equal("SmokeLoader",  r.LoaderFamily);
            Assert.Contains("aws:access_key", r.CloudCredentialHits);
        }

        [Fact]
        public void Pipeline_DoesNotDowngrade_ExistingHigherConfidence()
        {
            var r = Make("smokeloader marker");
            r.FamilyName       = "Pre-existing";
            r.FamilyConfidence = 99;
            r.FamilyReason     = "set by upstream";
            FamilyDetectorPipeline.RunOn(r);
            // Stealer detector doesn't match anything → FamilyName stays.
            Assert.Equal("Pre-existing", r.FamilyName);
            // Loader detector does match.
            Assert.Equal("SmokeLoader", r.LoaderFamily);
        }

        // ------------------------------------------------------------------
        // Regression coverage for the audit pass (see PR description).
        // ------------------------------------------------------------------

        [Fact]
        public void Stealer_PicksHighestConfidence_NotFirstListed()
        {
            // Both `banshee.lib` (80) and `rhadamanthys` (92) appear. The
            // former is listed first in the _markers table, but the result
            // must still be the higher-confidence Rhadamanthys match.
            var r = Make("banshee.lib helper", "rhadamanthys build 0.5.0");
            var m = StealerFamilyDetector.Detect(r);
            Assert.NotNull(m);
            Assert.Equal("Rhadamanthys", m!.Family);
            Assert.True(m.Confidence >= 90);
        }

        [Fact]
        public void Loader_PicksHighestConfidence_NotFirstListed()
        {
            // Same shape for loaders: `cloudeye` (80) before `darkgate` (90).
            var r = Make("CloudEyE log", "darkgate v6 ready");
            var m = LoaderFamilyDetector.Detect(r);
            Assert.NotNull(m);
            Assert.Equal("DarkGate", m!.Family);
            Assert.True(m.Confidence >= 90);
        }

        [Fact]
        public void Cloud_Webhooks_DetectedWhen_OnlyInUrlsFound()
        {
            // In real Analyzer runs URLs land in UrlsFound, not in the
            // curated StringHits. Before the fix this detector joined
            // StringHits alone and silently missed every webhook on real
            // samples. Verify that webhook indicators surface from the
            // URL extractor's output.
            var r = new AnalysisResult("x") { FileType = "PE" };
            r.UrlsFound.Add("https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX");
            r.UrlsFound.Add("https://discord.com/api/webhooks/1234567890/AbcDefGhIjK_LmNoPqRsTuVwXyZ12345");
            r.UrlsFound.Add("https://acme.webhook.office.com/webhookb2/abc-def@abcd/IncomingWebhook/123");
            var hits = CloudConfigDetector.Detect(r);
            Assert.Contains("slack:webhook",   hits);
            Assert.Contains("discord:webhook", hits);
            Assert.Contains("teams:webhook",   hits);
        }

        [Fact]
        public void Cloud_AwsAccessKey_DetectedWhen_OnlyInPackerHints()
        {
            // Same idea, but for the raw haystack hitting other source
            // lists. Tests that BuildRawHaystack walks PackerHints too.
            var r = new AnalysisResult("x") { FileType = "PE" };
            r.PackerHints.Add("aws marker AKIAIOSFODNN7EXAMPLE found inline");
            var hits = CloudConfigDetector.Detect(r);
            Assert.Contains("aws:access_key", hits);
        }

        [Fact]
        public void Haystack_TolerantOfNullEntries_InSourceLists()
        {
            // The legacy code crashed with an NRE if a parser upstream
            // pushed a null into StringHits / UrlsFound. The new builders
            // normalise to empty string defensively.
            var r = new AnalysisResult("x") { FileType = "PE" };
            r.StringHits.Add(null!);
            r.UrlsFound.Add(null!);
            r.PackerHints.Add(null!);
            r.MalwareSelfIdHits.Add(null!);
            // No exception expected.
            _ = StealerFamilyDetector.Detect(r);
            _ = LoaderFamilyDetector.Detect(r);
            _ = CloudConfigDetector.Detect(r);
        }
    }
}
