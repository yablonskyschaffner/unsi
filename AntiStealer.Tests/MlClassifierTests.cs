using System.Linq;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests
{
    public class MlClassifierTests
    {
        private static AnalysisResult Make(string fileType, params string[] strings)
        {
            var r = new AnalysisResult("x") { FileType = fileType };
            r.StringHits.AddRange(strings);
            return r;
        }

        // 3.1 -----------------------------------------------------------

        [Fact]
        public void FeatureVector_HasExpectedDim()
        {
            var r = Make("PE32", "hello", "world", "kernel32.dll");
            var v = MlFeatureVector.Extract(r);
            Assert.Equal(MlFeatureVector.Dim, v.Length);
        }

        [Fact]
        public void FeatureVector_FlagsBinaryFeatures_Correctly()
        {
            var r = Make("DLL",
                "some string", "another string");
            r.IsDll = true;
            r.IsSigned = true;
            r.IsDotNetLikely = true;
            r.PackerHints.Add("upx");
            r.ExecutableWritableSections.Add(".text");
            var v = MlFeatureVector.Extract(r);
            Assert.Equal(1f, v[11]); // IsDll
            Assert.Equal(1f, v[12]); // IsDotNet
            Assert.Equal(1f, v[13]); // IsSigned
            Assert.Equal(1f, v[14]); // Packer
            Assert.Equal(1f, v[15]); // RWX
        }

        [Fact]
        public void FeatureVector_FileTypeOneHot_IsExclusive()
        {
            // PE FileType should set one of the first 16 one-hot slots
            // to 1 and the rest in that block to 0.
            var r = Make("PE32", "x");
            var v = MlFeatureVector.Extract(r);
            int onCount = 0;
            for (int i = 16; i < 32; i++)
                if (v[i] > 0) onCount++;
            Assert.Equal(1, onCount);
        }

        [Fact]
        public void FeatureVector_HashedBag_Bucketed_AndNormalised()
        {
            var r = Make("Other",
                "abcdef ghijkl",
                "mnopqr stuvwx",
                "abcdef abcdef"); // some repeats
            var v = MlFeatureVector.Extract(r);
            // Last 32 dims should sum to ~1 after L1-normalisation.
            float sum = 0;
            for (int i = 32; i < 64; i++) sum += v[i];
            Assert.InRange(sum, 0.99, 1.01);
        }

        [Fact]
        public void FeatureVector_NumericFeatures_Clamped_To_Unit()
        {
            var r = Make("PE32");
            // Stuff far more strings than the normaliser expects.
            for (int i = 0; i < 5000; i++) r.StringHits.Add($"s{i}");
            var v = MlFeatureVector.Extract(r);
            Assert.InRange(v[0], 0.99, 1.01); // clamped to 1
        }

        // 3.2 -----------------------------------------------------------

        [Fact]
        public void Embedding_Hash_IsStable()
        {
            uint a = MlEmbedding.HashFnv1a("hello");
            uint b = MlEmbedding.HashFnv1a("hello");
            uint c = MlEmbedding.HashFnv1a("world");
            Assert.Equal(a, b);
            Assert.NotEqual(a, c);
        }

        // 3.3 / 3.4 / 3.5 -----------------------------------------------

        private static MlModelFile SmallModel()
        {
            // 2-class model — sums of feature halves separate "neg" / "pos".
            return new MlModelFile
            {
                Version = 1,
                FeatureDim = MlFeatureVector.Dim,
                Classes = new() { "neg", "pos" },
                Weights = new()
                {
                    Enumerable.Range(0, MlFeatureVector.Dim).Select(i => i < 32 ?  1f : -1f).ToArray(),
                    Enumerable.Range(0, MlFeatureVector.Dim).Select(i => i < 32 ? -1f :  1f).ToArray(),
                },
                Bias = new() { 0f, 0f },
                Platt = new()
                {
                    new() { A = 1.0, B = 0.0 },
                    new() { A = 1.0, B = 0.0 },
                },
            };
        }

        [Fact]
        public void MlModelFile_RoundtripsJson()
        {
            var m = SmallModel();
            var json = System.Text.Json.JsonSerializer.Serialize(m);
            var m2 = MlModelFile.FromJson(json);
            Assert.Equal(m.Classes, m2.Classes);
            Assert.Equal(m.FeatureDim, m2.FeatureDim);
        }

        [Fact]
        public void MlModelFile_RejectsMismatchedShapes()
        {
            var bad = new MlModelFile
            {
                FeatureDim = 4,
                Classes = new() { "a", "b" },
                Weights = new() { new float[] { 1, 1, 1, 1 } }, // only 1 row, expected 2
                Bias = new() { 0f, 0f },
            };
            Assert.Throws<System.IO.InvalidDataException>(() => bad.Validate());
        }

        [Fact]
        public void Classifier_ProducesTop1_OnSyntheticModel()
        {
            // Build a feature vector with strong "positive" signal in the
            // bag-of-strings half (dims 32..63) -> "pos" should win.
            var v = new float[MlFeatureVector.Dim];
            for (int i = 32; i < 64; i++) v[i] = 1f;
            var clf = new MlClassifier(SmallModel());
            var picks = clf.Score(v);
            Assert.Equal("pos", picks[0].Label);
            Assert.True(picks[0].Confidence > picks[1].Confidence);
        }

        [Fact]
        public void Classifier_Negation_Wins_When_LeftHalfHot()
        {
            var v = new float[MlFeatureVector.Dim];
            for (int i = 0; i < 32; i++) v[i] = 1f;
            var clf = new MlClassifier(SmallModel());
            var picks = clf.Score(v);
            Assert.Equal("neg", picks[0].Label);
        }

        [Fact]
        public void Classifier_ApplyTo_PopulatesAnalysisResult()
        {
            var r = Make("PE32");
            // Hot bag-of-strings → pos should win.
            for (int i = 0; i < 30; i++) r.StringHits.Add($"foo{i}");
            new MlClassifier(SmallModel()).ApplyTo(r);
            Assert.False(string.IsNullOrEmpty(r.MlFamilyPrediction));
            Assert.True(r.MlFamilyConfidence > 0);
        }

        [Fact]
        public void Classifier_Throws_OnFeatureLengthMismatch()
        {
            var clf = new MlClassifier(SmallModel());
            Assert.Throws<System.ArgumentException>(() => clf.Score(new float[10]));
        }

        // 3.6 -----------------------------------------------------------

        [Fact]
        public void Summary_Renders_FallbacksGracefully()
        {
            var r = Make("PE32");
            string s = MlSummaryGenerator.Render(r);
            Assert.Contains("Family: unknown", s);
            Assert.Contains("Risk:", s);
        }

        [Fact]
        public void Summary_Includes_TopIndicators_WhenPresent()
        {
            var r = Make("PE32");
            r.SuspiciousApiHits.Add("CryptUnprotectData");
            r.CryptoWalletHits.Add("0xdeadbeef");
            r.TelegramBotTokenHits.Add("1234567890:abc");
            r.PackerHints.Add("upx");
            r.ExecutableWritableSections.Add(".text");
            r.MlFamilyPrediction = "TestFamily";
            r.MlFamilyConfidence = 0.87;
            string s = MlSummaryGenerator.Render(r);
            Assert.Contains("TestFamily",       s);
            Assert.Contains("87%",              s);
            Assert.Contains("suspicious API",   s);
            Assert.Contains("crypto-wallet",    s);
            Assert.Contains("Telegram",         s);
            Assert.Contains("packer",           s);
            Assert.Contains("RWX",              s);
        }

        [Fact]
        public void Pipeline_PopulatesSummary_EvenWithoutModel()
        {
            var r = Make("PE32");
            r.FamilyName = "Legacy"; // legacy detector verdict
            MlPipeline.RunOn(r, classifier: null);
            Assert.False(string.IsNullOrEmpty(r.MlSummary));
            Assert.Contains("Legacy", r.MlSummary);
        }

        [Fact]
        public void Summary_UsesLegacyConfidence_WhenNoMlPrediction()
        {
            // Regression: the {1:0%} formatter previously consumed
            // r.MlFamilyConfidence directly. With no ML model loaded that
            // field stays at 0 and the summary always rendered "(0%)"
            // regardless of the legacy structural confidence. Verify the
            // fallback now scales FamilyConfidence (0..100) into [0,1].
            var r = Make("PE32");
            r.FamilyName        = "Legacy";
            r.FamilyConfidence  = 92;
            string s = MlSummaryGenerator.Render(r);
            Assert.Contains("Legacy",     s);
            Assert.Contains("92%",        s);
            Assert.DoesNotContain("(0%)", s);
        }

        [Fact]
        public void Pipeline_PopulatesSummary_WithModel()
        {
            var r = Make("PE32");
            for (int i = 0; i < 30; i++) r.StringHits.Add($"foo{i}");
            MlPipeline.RunOn(r, classifier: new MlClassifier(SmallModel()));
            Assert.False(string.IsNullOrEmpty(r.MlSummary));
            Assert.False(string.IsNullOrEmpty(r.MlFamilyPrediction));
        }

        // Platt ---------------------------------------------------------

        [Fact]
        public void Platt_IsBoundedTo_0_1()
        {
            var p = new PlattParams { A = 1.0, B = 0.0 };
            Assert.InRange(MlCalibrator.Platt(-1000, p), 0.0, 1.0);
            Assert.InRange(MlCalibrator.Platt( 1000, p), 0.0, 1.0);
        }

        [Fact]
        public void Softmax_SumsToOne_AndIsMonotone()
        {
            var p = MlCalibrator.Softmax(new[] { 1.0, 2.0, 3.0 });
            double sum = 0;
            foreach (var x in p) sum += x;
            Assert.InRange(sum, 0.999, 1.001);
            Assert.True(p[2] > p[1] && p[1] > p[0]);
        }

        // C21 — V2 feature vector / per-format dispatcher ---------------

        [Fact]
        public void C21_FeatureVectorV2_HasExpectedDim_AndV1PrefixPreserved()
        {
            var r = Make("PE32", "hello", "kernel32.dll");
            r.IsDll = true;
            r.IsSigned = true;
            var v1 = MlFeatureVector.Extract(r);
            var v2 = MlFeatureVectorV2.Extract(r);
            Assert.Equal(MlFeatureVectorV2.Dim, v2.Length);
            Assert.Equal(256, v2.Length);
            // V1 prefix [0..63] must be byte-equal to V1 extraction.
            for (int i = 0; i < MlFeatureVector.Dim; i++)
                Assert.Equal(v1[i], v2[i]);
        }

        [Fact]
        public void C21_FeatureVectorV2_PopulatesUrlHostAndYaraBuckets()
        {
            var r = Make("PE32", "x");
            r.UrlsFound.Add("https://evil.example.org/payload.bin");
            r.YaraHits.Add("Generic_Stealer");
            var v = MlFeatureVectorV2.Extract(r);
            // URL host block [144..159] and YARA block [160..175] must
            // have at least one non-zero entry.
            bool urlSet = false, yaraSet = false;
            for (int i = 144; i < 160; i++) if (v[i] > 0) urlSet = true;
            for (int i = 160; i < 176; i++) if (v[i] > 0) yaraSet = true;
            Assert.True(urlSet,  "URL host bucket should be set");
            Assert.True(yaraSet, "YARA hit bucket should be set");
        }

        [Fact]
        public void C21_FeatureVectorV2_FormatOneHot_PicksFamily()
        {
            var r = Make("PE32", "x");
            r.FormatFamily = "PE";
            var v = MlFeatureVectorV2.Extract(r);
            // Exactly one slot in [208..223] should be 1, rest 0.
            int hits = 0;
            for (int i = 208; i < 224; i++) if (v[i] == 1f) hits++;
            Assert.Equal(1, hits);
        }

        [Fact]
        public void C21_FeatureVectorV2_DecisiveFloorFlagsRecorded()
        {
            var r = Make("PE32", "x");
            r.AppliedFloors.Add("DecisiveBrowserChain=>90");
            r.AppliedFloors.Add("PowerShellEncodedCradle=>90");
            var v = MlFeatureVectorV2.Extract(r);
            // First two floor flags should be set; rest zero.
            Assert.Equal(1f, v[248]);
            Assert.Equal(1f, v[249]);
            for (int i = 250; i < 256; i++) Assert.Equal(0f, v[i]);
        }

        [Fact]
        public void C21_FeatureVectorV2_SignerFlags_AreObservable()
        {
            var r = Make("PE32", "x");
            r.IsSigned = true;
            r.AllowlistMatched = true;
            r.Signer = "Microsoft Corporation";
            r.ImphashFamilyMatch = "LummaC2";
            var v = MlFeatureVectorV2.Extract(r);
            Assert.Equal(1f, v[232]); // IsSigned
            Assert.Equal(1f, v[233]); // AllowlistMatched
            Assert.Equal(1f, v[234]); // Signer present
            Assert.Equal(1f, v[235]); // ImphashFamilyMatch present
        }

        [Fact]
        public void C21_MlPipeline_NoModelPresent_DoesNotThrow_AndPopulatesSummary()
        {
            // When no model files exist on disk, the V2 dispatcher must
            // gracefully fall through. We can't easily mock the model
            // file system, so we just verify the call doesn't throw and
            // that MlSummary is still populated (legacy path).
            var r = Make("PE32", "x");
            MlPipeline.RunOn(r);
            Assert.NotNull(r.MlSummary);
        }
    }
}
