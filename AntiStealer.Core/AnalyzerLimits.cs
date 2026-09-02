// Section 22.2 — central place for previously inline magic numbers used by the
// analyzer pipeline. Values match the historical defaults; this file only
// changes their location, not their meaning.
//
// Anything that was a `private const int Something = …;` inside Analyzer.cs and
// that other layers (tests, future plugins, CLI) might want to override should
// move here over time. Keeping a single place also lets us document units in
// one spot.
namespace AntiStealerOneExe
{
    /// <summary>
    /// Static, immutable limits used by the analyzer pipeline.
    /// </summary>
    public static class AnalyzerLimits
    {
        // Maximum number of analysis-text characters fed to the regex / needle
        // sweep. 2 MiB is enough to cover all but the largest single-file
        // payloads while keeping regex backtracking within budget.
        public const int MaxSearchTextChars = 2_000_000;

        // Section 5.6 — small samples (e.g. an .lnk file or a tiny shell script)
        // do not need a 2 MiB analysis-text buffer; in fact the StringBuilder
        // is the dominant allocation when the input itself is <50 KiB. Pick a
        // tighter cap based on file size so we don't pre-grow the buffer.
        // The returned value is always >= 64 KiB and <= MaxSearchTextChars.
        public static int AdaptiveSearchTextCap(long fileSize)
        {
            if (fileSize <= 0)              return 64 * 1024;
            if (fileSize < 64 * 1024)       return 64 * 1024;          // 64 KiB
            if (fileSize < 1 * 1024 * 1024) return 256 * 1024;         // 256 KiB
            if (fileSize < 8 * 1024 * 1024) return 512 * 1024;         // 512 KiB
            return MaxSearchTextChars;                                  // 2 MiB
        }

        // Per-regex execution budget. Compiled regexes occasionally hit
        // pathological inputs; we treat a timeout as "no match".
        public const int RegexTimeoutMs = 200;

        // Default cap for the read-prefix used by Analyze(). Files larger than
        // this still get hashed in full — only the prefix is fed to detectors.
        public const int DefaultMaxReadPrefixBytes = 20 * 1024 * 1024;

        // Default caps for extracted strings / URLs.
        public const int DefaultMaxExtractedUrls = 500;
        public const int DefaultMaxAsciiStrings  = 50_000;
        public const int DefaultMaxUnicodeStrings = 25_000;

        // Maximum length of a single string we keep as evidence. Anything
        // longer is truncated to avoid blowing up the analysis-text buffer.
        public const int MaxStringEvidenceLength = 2048;

        // Cap on the number of distinct regex matches we surface per kind.
        public const int MaxDistinctRegexMatches = 200;

        // Per-rule timeout for the optional external YARA invocation (ms).
        public const int YaraPerRuleTimeoutMs = 8_000;

        // Cap on the number of YARA rule files invoked per scan.
        public const int YaraMaxRuleFiles = 64;

        // Cap on the number of YARA hits we surface per sample.
        public const int YaraMaxHits = 64;

        // HttpClient timeout for the local server-side classifier.
        public const int ClassifierHttpTimeoutSeconds = 4;
    }
}
