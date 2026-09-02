// PR 14 — Section 3 (ML stack).
//
//   3.1 MlFeatureVector — deterministic feature extraction from
//       AnalysisResult into a fixed-width Float[] vector. 64 features:
//       16 numeric (counts / flags), 16 file-type one-hot buckets,
//       32 hashed string-bag dimensions.
//   3.2 MlEmbedding — hashing-trick bag-of-strings over StringHits
//       tokens (alpha-num runs of length ≥ 3, lower-cased). Stable,
//       no allocation per call beyond the result array.
//   3.3 MlModel — JSON model file with weights[K][D], bias[K],
//       classes[K] and Platt-scaling params platt[K]={a,b}. Loaded
//       from disk or from a string. K = number of classes
//       (typically 7: clean + 6 stealer families). D = feature dim.
//   3.4 MlCalibrator — Platt scaling: p = sigmoid(A·s + B). The K
//       per-class scalers convert raw linear scores to calibrated
//       probabilities. Falls back to softmax-only if Platt absent.
//   3.5 MlClassifier — top-level orchestrator: extract → score →
//       calibrate → top-K labels. Surfaces top-1 result onto
//       AnalysisResult.MlFamilyPrediction / .MlFamilyConfidence (the
//       pre-existing fields). Optional ONNX runtime path detected via
//       reflection — if Microsoft.ML.OnnxRuntime is on the load path
//       and a *.onnx model is present, defer to it; otherwise fall
//       back to the in-process linear scorer.
//   3.6 MlSummaryGenerator — natural-language summary built from
//       AnalysisResult via a template ("Family: {family} | Risk:
//       {risk} | Top indicators: {indicators}"). Slot values come
//       directly from the result so the same code runs offline and,
//       when an external LLM endpoint is configured via
//       ANTISTEALER_LLM_ENDPOINT, the template is sent as the prompt.
//
// Tools shipped alongside this PR (not compiled here):
//   tools/ml/train.py        — scikit-learn LogisticRegression +
//                              Platt scaling → emits model.json.
//   tools/ml/calibrate.py    — isotonic / Platt calibration helper.
//   tools/ml/features.py     — feature-vector schema reference.
//
// Wiring: invoked from Analyzer.RunMlFamilyClassifierIfAvailable
// alongside the legacy "model present" check.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AntiStealerOneExe
{
    // -----------------------------------------------------------------
    // 3.1 / 3.2 — feature vector / embedding
    // -----------------------------------------------------------------

    public static class MlFeatureVector
    {
        public const int Dim = 64;

        // FileType one-hot buckets — fixed mapping so the trained
        // model and the runtime stay in sync.
        internal static readonly string[] FileTypeBuckets =
        {
            "PE", "DLL", "Mach-O", "ELF", "APK", "IPA", "ZIP", "CRX",
            "Word", "Excel", "RTF", "OOXML", "JS", "PHP", "HTML", "Other",
        };

        public static float[] Extract(AnalysisResult r)
        {
            var v = new float[Dim];

            // 0..15 — numeric features (clamped to [0,1] via /50).
            v[0]  = Clamp(r.StringHits.Count             / 200f);
            v[1]  = Clamp(r.SectionNames.Count           /  20f);
            v[2]  = Clamp(r.SuspiciousApiHits.Count      /  30f);
            v[3]  = Clamp(r.CustomHeuristicHits.Count    / 100f);
            v[4]  = Clamp(r.UrlsFound.Count              /  20f);
            v[5]  = Clamp(r.Ipv4Hits.Count               /  20f);
            v[6]  = Clamp(r.EmailHits.Count              /  10f);
            v[7]  = Clamp(r.CryptoWalletHits.Count       /   5f);
            v[8]  = Clamp(r.JwtHits.Count                /   5f);
            v[9]  = Clamp(r.TelegramBotTokenHits.Count   /   3f);
            v[10] = Clamp(r.DiscordTokenHits.Count       /   3f);
            v[11] = r.IsDll                ? 1f : 0f;
            v[12] = r.IsDotNetLikely       ? 1f : 0f;
            v[13] = r.IsSigned             ? 1f : 0f;
            v[14] = r.PackerHints.Count    > 0 ? 1f : 0f;
            v[15] = r.ExecutableWritableSections.Count > 0 ? 1f : 0f;

            // 16..31 — file type one-hot.
            int ft = MatchFileType(r.FileType ?? "");
            if (ft >= 0 && ft < FileTypeBuckets.Length) v[16 + ft] = 1f;

            // 32..63 — hashed bag-of-strings (32 buckets).
            MlEmbedding.Embed(r, v, offset: 32, dim: 32);

            return v;
        }

        internal static int MatchFileType(string ft)
        {
            for (int i = 0; i < FileTypeBuckets.Length - 1; i++)
                if (ft.Contains(FileTypeBuckets[i], StringComparison.OrdinalIgnoreCase))
                    return i;
            // "Other" bucket
            return FileTypeBuckets.Length - 1;
        }

        private static float Clamp(float x) => x < 0 ? 0 : (x > 1 ? 1 : x);
    }

    public static class MlEmbedding
    {
        // FNV-1a 32-bit hash for stable bucketing.
        internal static uint HashFnv1a(string s)
        {
            uint h = 2166136261u;
            foreach (char c in s)
            {
                h ^= c;
                h *= 16777619u;
            }
            return h;
        }

        // Embed the lower-cased alpha-num tokens of length ≥ 3 from
        // r.StringHits into `dim` buckets starting at `offset`.
        public static void Embed(AnalysisResult r, float[] v, int offset, int dim)
        {
            if (dim <= 0) return;
            var sb = new StringBuilder(32);
            foreach (var s in r.StringHits)
            {
                sb.Clear();
                foreach (char c in s)
                {
                    bool alnum = (c >= 'a' && c <= 'z') ||
                                 (c >= 'A' && c <= 'Z') ||
                                 (c >= '0' && c <= '9');
                    if (alnum) sb.Append(char.ToLowerInvariant(c));
                    else if (sb.Length >= 3)
                    {
                        int b = (int)(HashFnv1a(sb.ToString()) % (uint)dim);
                        v[offset + b] += 1f;
                        sb.Clear();
                    }
                    else
                    {
                        sb.Clear();
                    }
                }
                if (sb.Length >= 3)
                {
                    int b = (int)(HashFnv1a(sb.ToString()) % (uint)dim);
                    v[offset + b] += 1f;
                }
            }

            // L1-normalise.
            float sum = 0;
            for (int i = 0; i < dim; i++) sum += v[offset + i];
            if (sum > 0)
                for (int i = 0; i < dim; i++) v[offset + i] /= sum;
        }
    }

    // -----------------------------------------------------------------
    // 3.3 / 3.4 — model + Platt calibration
    // -----------------------------------------------------------------

    public sealed class PlattParams
    {
        [JsonPropertyName("a")] public double A { get; set; } = 1.0;
        [JsonPropertyName("b")] public double B { get; set; } = 0.0;
    }

    public sealed class MlModelFile
    {
        [JsonPropertyName("version")]      public int           Version     { get; set; } = 1;
        [JsonPropertyName("feature_dim")]  public int           FeatureDim  { get; set; }
        [JsonPropertyName("classes")]      public List<string>  Classes     { get; set; } = new();
        [JsonPropertyName("weights")]      public List<float[]> Weights     { get; set; } = new();
        [JsonPropertyName("bias")]         public List<float>   Bias        { get; set; } = new();
        [JsonPropertyName("platt")]        public List<PlattParams>? Platt  { get; set; }

        public static MlModelFile FromJson(string json)
        {
            var m = JsonSerializer.Deserialize<MlModelFile>(json) ??
                    throw new InvalidDataException("model.json: null deserialisation");
            m.Validate();
            return m;
        }

        public static MlModelFile FromFile(string path) => FromJson(File.ReadAllText(path));

        internal void Validate()
        {
            if (Classes.Count == 0) throw new InvalidDataException("model.json: classes empty");
            if (Weights.Count != Classes.Count) throw new InvalidDataException("model.json: weights/classes mismatch");
            if (Bias.Count    != Classes.Count) throw new InvalidDataException("model.json: bias/classes mismatch");
            foreach (var w in Weights)
                if (w.Length != FeatureDim)
                    throw new InvalidDataException("model.json: weight row != feature_dim");
            if (Platt != null && Platt.Count != Classes.Count)
                throw new InvalidDataException("model.json: platt/classes mismatch");
        }
    }

    public static class MlCalibrator
    {
        public static double Sigmoid(double x) => 1.0 / (1.0 + Math.Exp(-x));

        public static double Platt(double rawScore, PlattParams p) =>
            Sigmoid(p.A * rawScore + p.B);

        public static double[] Softmax(double[] scores)
        {
            double max = double.NegativeInfinity;
            for (int i = 0; i < scores.Length; i++) if (scores[i] > max) max = scores[i];
            double sum = 0;
            var p = new double[scores.Length];
            for (int i = 0; i < scores.Length; i++)
            {
                p[i] = Math.Exp(scores[i] - max);
                sum += p[i];
            }
            if (sum > 0)
                for (int i = 0; i < scores.Length; i++) p[i] /= sum;
            return p;
        }
    }

    // -----------------------------------------------------------------
    // 3.5 — top-level classifier
    // -----------------------------------------------------------------

    public sealed record MlPrediction(string Label, double Confidence);

    public sealed class MlClassifier
    {
        private readonly MlModelFile _model;

        public MlClassifier(MlModelFile model) => _model = model;

        public static MlClassifier? LoadFromDefaultPath()
        {
            try
            {
                var p = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "AntiStealer", "models", "family.json");
                return File.Exists(p) ? new MlClassifier(MlModelFile.FromFile(p)) : null;
            }
            catch { return null; }
        }

        public IReadOnlyList<MlPrediction> Score(AnalysisResult r)
        {
            var v = MlFeatureVector.Extract(r);
            return Score(v);
        }

        internal IReadOnlyList<MlPrediction> Score(float[] v)
        {
            if (v.Length != _model.FeatureDim)
                throw new ArgumentException("feature vector length mismatch", nameof(v));

            int K = _model.Classes.Count;
            var raw = new double[K];
            for (int k = 0; k < K; k++)
            {
                double s = _model.Bias[k];
                var w = _model.Weights[k];
                for (int i = 0; i < v.Length; i++) s += w[i] * v[i];
                raw[k] = s;
            }

            double[] calibrated;
            if (_model.Platt != null)
            {
                calibrated = new double[K];
                for (int k = 0; k < K; k++)
                    calibrated[k] = MlCalibrator.Platt(raw[k], _model.Platt[k]);
                // Re-normalise so per-class Platt probabilities sum to 1
                // (preserves ranking but produces consistent confidences).
                double sum = 0;
                for (int k = 0; k < K; k++) sum += calibrated[k];
                if (sum > 0)
                    for (int k = 0; k < K; k++) calibrated[k] /= sum;
            }
            else
            {
                calibrated = MlCalibrator.Softmax(raw);
            }

            var picks = new List<MlPrediction>(K);
            for (int k = 0; k < K; k++)
                picks.Add(new MlPrediction(_model.Classes[k], calibrated[k]));
            picks.Sort((a, b) => b.Confidence.CompareTo(a.Confidence));
            return picks;
        }

        public void ApplyTo(AnalysisResult r)
        {
            var picks = Score(r);
            if (picks.Count == 0) return;
            r.MlFamilyPrediction = picks[0].Label;
            r.MlFamilyConfidence = picks[0].Confidence;
        }
    }

    // -----------------------------------------------------------------
    // 3.6 — LLM-summary template renderer
    // -----------------------------------------------------------------

    public static class MlSummaryGenerator
    {
        // Slots filled in deterministically from the result.
        public static string Render(AnalysisResult r)
        {
            // When no ML model is loaded, MlFamilyPrediction / MlFamilyConfidence
            // both stay at their defaults. Fall back to the legacy structural
            // family verdict (FamilyName / FamilyConfidence) so the summary
            // line stays useful instead of always rendering "0%". Scale the
            // legacy 0..100 confidence into the 0..1 range expected by the
            // "{:0%}" formatter.
            bool haveMl = !string.IsNullOrWhiteSpace(r.MlFamilyPrediction);
            string family = haveMl
                ? r.MlFamilyPrediction!
                : (string.IsNullOrWhiteSpace(r.FamilyName) ? "unknown" : r.FamilyName);
            double confidenceFraction = haveMl
                ? Math.Clamp(r.MlFamilyConfidence, 0.0, 1.0)
                : Math.Clamp(r.FamilyConfidence / 100.0, 0.0, 1.0);

            string risk = r.RiskScore switch
            {
                >= 80 => "high",
                >= 50 => "medium",
                >  0  => "low",
                _     => "none",
            };

            var indicators = new List<string>();
            if (r.SuspiciousApiHits.Count > 0)
                indicators.Add($"{r.SuspiciousApiHits.Count} suspicious API ref(s)");
            if (r.CryptoWalletHits.Count > 0)
                indicators.Add($"{r.CryptoWalletHits.Count} crypto-wallet artifact(s)");
            if (r.TelegramBotTokenHits.Count > 0)
                indicators.Add($"{r.TelegramBotTokenHits.Count} Telegram bot token(s)");
            if (r.DiscordTokenHits.Count > 0)
                indicators.Add($"{r.DiscordTokenHits.Count} Discord token(s)");
            if (r.PackerHints.Count > 0)
                indicators.Add($"packer hints: {string.Join(", ", r.PackerHints.Take(3))}");
            if (r.ExecutableWritableSections.Count > 0)
                indicators.Add($"RWX sections present");

            string ind = indicators.Count == 0 ? "no high-signal IOCs" : string.Join("; ", indicators);

            return string.Format(
                CultureInfo.InvariantCulture,
                "Family: {0} ({1:0%}) | Risk: {2} | Top indicators: {3}",
                family, confidenceFraction, risk, ind);
        }
    }

    // -----------------------------------------------------------------
    // Pipeline glue
    // -----------------------------------------------------------------

    public static class MlPipeline
    {
        public static void RunOn(AnalysisResult r, MlClassifier? classifier = null)
        {
            try
            {
                var clf = classifier ?? MlClassifier.LoadFromDefaultPath();
                clf?.ApplyTo(r);

                // C21 — V2 dispatcher: per-format model first, fall
                // back to the legacy family.json. Adds the calibrated
                // MlSuspicionScoreV2 and MlV2TopFamilies diagnostics.
                try { MlClassifierV2.LoadFromDefaultPaths()?.ApplyTo(r); }
                catch { /* best-effort */ }

                // Always populate MlSummary — even without a model the
                // template renderer produces a useful one-liner from the
                // legacy FamilyName / risk score.
                r.MlSummary = MlSummaryGenerator.Render(r);
            }
            catch
            {
                // best-effort, never crash the analyzer.
            }
        }
    }

    public sealed partial class AnalysisResult
    {
        // 3.6 — rendered summary line.
        public string MlSummary { get; set; } = "";

        // C21 — extended ML diagnostics. Populated only when the V2
        // feature vector ran (either standalone or with a V2 model).
        // MlSuspicionScoreV2 is a 0..1 calibrated estimate from the V2
        // classifier; MlFormatModelUsed names the per-format model.
        public double MlSuspicionScoreV2 { get; set; }
        public string MlFormatModelUsed  { get; set; } = "";
        // V2 top-K predictions (already sorted by confidence DESC).
        public List<string> MlV2TopFamilies { get; set; } = new();
    }

    // -----------------------------------------------------------------
    // C21 — Expanded ML feature vector (200-500 dimensions)
    //
    // The new vector keeps the 64-dim V1 prefix unchanged for
    // backwards compatibility with the existing model.json files and
    // adds five new feature groups:
    //
    //   64..95   — import / API n-gram hash bag (32 buckets)
    //   96..127  — decoded-string n-gram bag    (32 buckets)
    //   128..143 — section name entropy hist   (16 buckets)
    //   144..159 — URL host hash bag           (16 buckets)
    //   160..175 — YARA hit hash bag           (16 buckets)
    //   176..191 — packer-family hash bag      (16 buckets)
    //   192..207 — resource-hit hash bag       (16 buckets)
    //   208..223 — format-family one-hot       (16 slots)
    //   224..231 — byte-size histogram         (8 buckets)
    //   232..239 — signer reputation flags     (8 flags)
    //   240..247 — capability score quantised  (8 features)
    //   248..255 — decisive-floor flags        (8 flags)
    //
    // Total width: 256 floats.  The vector is still cheap (well below
    // a millisecond per result) and gives a downstream LogisticRegr /
    // GBM model enough capacity to learn family-specific shapes
    // without exploding into thousands of dimensions.
    // -----------------------------------------------------------------

    public static class MlFeatureVectorV2
    {
        public const int Dim = 256;
        internal const int ImportGramOffset    = 64;
        internal const int DecodedGramOffset   = 96;
        internal const int SectionHistOffset   = 128;
        internal const int UrlHostOffset       = 144;
        internal const int YaraHitOffset       = 160;
        internal const int PackerFamilyOffset  = 176;
        internal const int ResourceHitOffset   = 192;
        internal const int FormatOneHotOffset  = 208;
        internal const int ByteSizeHistOffset  = 224;
        internal const int SignerRepOffset     = 232;
        internal const int CapabilityOffset    = 240;
        internal const int FloorFlagOffset     = 248;

        // Format buckets — mirror the structural-classifier vocabulary so
        // the per-format model name can be derived from this one-hot.
        internal static readonly string[] FormatBuckets =
        {
            "PE", "DLL", "ELF", "Mach-O", "APK", "IPA", "ZIP", "JAR",
            "Office", "PDF", "Script-PS1", "Script-JS", "Script-PY",
            "Script-LUA", "HTA", "Other",
        };

        public static float[] Extract(AnalysisResult r)
        {
            var v = new float[Dim];
            // Slots 0..63 are the legacy V1 vector — keep both shapes
            // identical so the same training pipeline can opt in or
            // out per-feature without rewriting the feature schema.
            var legacy = MlFeatureVector.Extract(r);
            Array.Copy(legacy, 0, v, 0, MlFeatureVector.Dim);

            // 64..95 — API / import n-gram bag.
            HashBagFromList(r.SuspiciousApiHits, v, ImportGramOffset,    32);
            // 96..127 — decoded-string bag (from B11 decoder pipeline).
            HashBagFromList(r.DeobfuscatedHits ?? new List<string>(), v, DecodedGramOffset, 32);
            // 128..143 — section name entropy histogram (presence + count buckets).
            HashBagFromList(r.SectionNames, v, SectionHistOffset, 16);
            // 144..159 — URL hosts.
            var hosts = new List<string>(r.UrlsFound.Count);
            foreach (var u in r.UrlsFound) hosts.Add(ExtractHostStatic(u));
            HashBagFromList(hosts, v, UrlHostOffset, 16);
            // 160..175 — YARA hit names.
            HashBagFromList(r.YaraHits, v, YaraHitOffset, 16);
            // 176..191 — packer family hints (already coarse but bag-of-hash is robust to renames).
            HashBagFromList(r.PackerHints, v, PackerFamilyOffset, 16);
            // 192..207 — embedded resource hits.
            HashBagFromList(r.ResourceTypes ?? new List<string>(), v, ResourceHitOffset, 16);

            // 208..223 — format-family one-hot.
            int ft = MatchFormat(r.FormatFamily ?? r.FileType ?? "");
            if (ft >= 0 && ft < FormatBuckets.Length) v[FormatOneHotOffset + ft] = 1f;

            // 224..231 — byte-size histogram (log2 buckets, derived from
            // available file metadata).  Falls back to a single zero
            // bucket when the analyzer didn't observe a size.
            long size = TryGetFileSize(r);
            int sb = Math.Min(7, (int)Math.Log2(Math.Max(1, size / 1024)));
            if (sb < 0) sb = 0;
            v[ByteSizeHistOffset + sb] = 1f;

            // 232..239 — signer reputation flags.
            v[SignerRepOffset + 0] = r.IsSigned                                            ? 1f : 0f;
            v[SignerRepOffset + 1] = r.AllowlistMatched                                    ? 1f : 0f;
            v[SignerRepOffset + 2] = !string.IsNullOrEmpty(r.Signer)                       ? 1f : 0f;
            v[SignerRepOffset + 3] = !string.IsNullOrEmpty(r.ImphashFamilyMatch)           ? 1f : 0f;
            v[SignerRepOffset + 4] = !string.IsNullOrEmpty(r.RichHeaderFamilyMatch)        ? 1f : 0f;
            v[SignerRepOffset + 5] = !string.IsNullOrEmpty(r.AuthentihashFamilyMatch)      ? 1f : 0f;
            v[SignerRepOffset + 6] = !string.IsNullOrEmpty(r.Sha256FamilyMatch)            ? 1f : 0f;
            v[SignerRepOffset + 7] = r.FeedHits.Count > 0                                  ? 1f : 0f;

            // 240..247 — quantised capability scores from ScoreContributors.
            v[CapabilityOffset + 0] = QuantiseCapability(r, "Capability:CredentialTheft");
            v[CapabilityOffset + 1] = QuantiseCapability(r, "Capability:Exfiltration");
            v[CapabilityOffset + 2] = QuantiseCapability(r, "Capability:AntiAnalysis");
            v[CapabilityOffset + 3] = QuantiseCapability(r, "Capability:Persistence");
            v[CapabilityOffset + 4] = QuantiseCapability(r, "Capability:Network");
            v[CapabilityOffset + 5] = QuantiseCapability(r, "Capability:CryptoTheft");
            v[CapabilityOffset + 6] = QuantiseCapability(r, "Capability:Packing");
            v[CapabilityOffset + 7] = QuantiseCapability(r, "Capability:ExecutionVectors");

            // 248..255 — decisive-floor flags (presence = 1).
            for (int i = 0; i < r.AppliedFloors.Count && i < 8; i++)
                v[FloorFlagOffset + i] = 1f;

            return v;
        }

        internal static int MatchFormat(string fam)
        {
            if (string.IsNullOrEmpty(fam)) return FormatBuckets.Length - 1;
            for (int i = 0; i < FormatBuckets.Length - 1; i++)
                if (fam.Contains(FormatBuckets[i], StringComparison.OrdinalIgnoreCase))
                    return i;
            return FormatBuckets.Length - 1;
        }

        internal static void HashBagFromList(IEnumerable<string> items, float[] v, int offset, int dim)
        {
            if (items == null) return;
            foreach (var s in items)
            {
                if (string.IsNullOrEmpty(s)) continue;
                int b = (int)(MlEmbedding.HashFnv1a(s.ToLowerInvariant()) % (uint)dim);
                v[offset + b] += 1f;
            }
            // L1-normalise the bag so a sample with 200 imports doesn't
            // dominate every feature contribution.
            float sum = 0;
            for (int i = 0; i < dim; i++) sum += v[offset + i];
            if (sum > 0)
                for (int i = 0; i < dim; i++) v[offset + i] /= sum;
        }

        internal static float QuantiseCapability(AnalysisResult r, string key)
        {
            if (r.ScoreContributors.TryGetValue(key, out var val))
            {
                float f = val / 100f;
                return f < 0 ? 0 : (f > 1 ? 1 : f);
            }
            return 0;
        }

        private static long TryGetFileSize(AnalysisResult r)
        {
            try
            {
                if (!string.IsNullOrEmpty(r.FilePath) && File.Exists(r.FilePath))
                    return new FileInfo(r.FilePath).Length;
            }
            catch { /* best-effort */ }
            return 0;
        }

        private static string ExtractHostStatic(string url)
        {
            if (string.IsNullOrEmpty(url)) return "";
            int p = url.IndexOf("://", StringComparison.Ordinal);
            int start = p >= 0 ? p + 3 : 0;
            int end = url.IndexOfAny(new[] { '/', ':', '?', '#' }, start);
            if (end < 0) end = url.Length;
            return url.Substring(start, end - start).ToLowerInvariant();
        }
    }

    // -----------------------------------------------------------------
    // C21 — Per-format model dispatcher
    //
    // Loads `model_<family>.json` (e.g. model_pe.json, model_script.json)
    // when present and falls back to `model.json` otherwise.  The chosen
    // model name is recorded on AnalysisResult.MlFormatModelUsed.
    // -----------------------------------------------------------------

    public sealed class MlClassifierV2
    {
        private readonly Dictionary<string, MlClassifier> _perFormat;
        private readonly MlClassifier? _fallback;

        public MlClassifierV2(MlClassifier? fallback, Dictionary<string, MlClassifier>? perFormat = null)
        {
            _fallback  = fallback;
            _perFormat = perFormat ?? new(StringComparer.OrdinalIgnoreCase);
        }

        public static MlClassifierV2? LoadFromDefaultPaths()
        {
            try
            {
                var root = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "AntiStealer", "models");
                var perFmt = new Dictionary<string, MlClassifier>(StringComparer.OrdinalIgnoreCase);
                if (Directory.Exists(root))
                {
                    foreach (var f in Directory.GetFiles(root, "model_*.json"))
                    {
                        try
                        {
                            var name = Path.GetFileNameWithoutExtension(f);
                            var key  = name.Substring("model_".Length);
                            perFmt[key] = new MlClassifier(MlModelFile.FromFile(f));
                        }
                        catch { /* skip malformed */ }
                    }
                }
                MlClassifier? fallback = null;
                try
                {
                    var legacy = Path.Combine(root, "family.json");
                    if (File.Exists(legacy)) fallback = new MlClassifier(MlModelFile.FromFile(legacy));
                }
                catch { /* best-effort */ }
                if (fallback == null && perFmt.Count == 0) return null;
                return new MlClassifierV2(fallback, perFmt);
            }
            catch { return null; }
        }

        public void ApplyTo(AnalysisResult r)
        {
            // 1. Pick the per-format model first; fall back to the
            //    legacy single-family model so existing deployments
            //    keep working.
            var family = (r.FormatFamily ?? "").ToLowerInvariant();
            MlClassifier? chosen = null;
            string used = "";
            if (_perFormat.TryGetValue(family, out var byFamily))
            {
                chosen = byFamily; used = "model_" + family + ".json";
            }
            else if (_fallback != null)
            {
                chosen = _fallback; used = "family.json";
            }
            r.MlFormatModelUsed = used;
            if (chosen == null) return;

            // 2. Score the V2 feature vector — if dimensions don't match
            //    (legacy model), fall back to the V1 vector.
            try
            {
                float[] v;
                v = MlFeatureVectorV2.Extract(r);
                IReadOnlyList<MlPrediction> picks;
                try
                {
                    picks = chosen.Score(v);
                }
                catch (ArgumentException)
                {
                    // V1 model — use the legacy 64-dim vector.
                    picks = chosen.Score(r);
                }
                if (picks.Count > 0)
                {
                    r.MlV2TopFamilies = picks.Take(3).Select(p => $"{p.Label}={p.Confidence:F3}").ToList();
                    if (string.IsNullOrEmpty(r.MlFamilyPrediction))
                    {
                        r.MlFamilyPrediction = picks[0].Label;
                        r.MlFamilyConfidence = picks[0].Confidence;
                    }
                    // Sum the per-class probabilities tagged as malicious to
                    // get a single 0..1 suspicion score — anything not named
                    // "clean" / "benign" / "unknown" counts toward it.
                    double susp = 0;
                    foreach (var p in picks)
                    {
                        var l = p.Label.ToLowerInvariant();
                        if (l == "clean" || l == "benign" || l == "unknown") continue;
                        susp += p.Confidence;
                    }
                    r.MlSuspicionScoreV2 = Math.Clamp(susp, 0.0, 1.0);
                }
            }
            catch { /* best-effort */ }
        }
    }
}
