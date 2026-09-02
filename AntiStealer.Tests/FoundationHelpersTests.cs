using System.Text.Json;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests
{
    /// <summary>
    /// Section 22 — small, fast unit tests for the new shared helpers
    /// (HexUtil, JsonOptionsRegistry, RiskLevel, AnalyzerLimits).
    /// These mostly act as regression guards: if someone accidentally
    /// breaks the singleton identity of JsonOptionsRegistry, or flips a
    /// limit constant, these tests fail loudly.
    /// </summary>
    public class FoundationHelpersTests
    {
        // ---------- HexUtil --------------------------------------------------

        [Fact]
        public void HexUtil_ToLowerHex_EmptyArray_ReturnsEmptyString()
        {
            Assert.Equal(string.Empty, HexUtil.ToLowerHex(System.Array.Empty<byte>()));
        }

        [Fact]
        public void HexUtil_ToLowerHex_KnownVectors()
        {
            // SHA-256("") and a couple of small inputs — pinned so any change
            // in encoding (case, byte-order) becomes obvious.
            Assert.Equal("00",       HexUtil.ToLowerHex(new byte[] { 0 }));
            Assert.Equal("ff",       HexUtil.ToLowerHex(new byte[] { 0xff }));
            Assert.Equal("deadbeef", HexUtil.ToLowerHex(new byte[] { 0xde, 0xad, 0xbe, 0xef }));
        }

        [Fact]
        public void HexUtil_ToLowerHex_AlwaysLowercase()
        {
            // 0xAB encodes as 'ab' (not 'AB'). Guards against an accidental
            // switch back to Convert.ToHexString() without ToLowerInvariant.
            var hex = HexUtil.ToLowerHex(new byte[] { 0xAB, 0xCD, 0xEF });
            Assert.Equal("abcdef", hex);
            Assert.Equal(hex.ToLowerInvariant(), hex);
        }

        // ---------- JsonOptionsRegistry --------------------------------------

        [Fact]
        public void JsonOptionsRegistry_Indented_IsIndentedAndSingleton()
        {
            var a = JsonOptionsRegistry.Indented;
            var b = JsonOptionsRegistry.Indented;
            Assert.Same(a, b);                 // same instance — no per-call alloc
            Assert.True(a.WriteIndented);
        }

        [Fact]
        public void JsonOptionsRegistry_CamelCase_IsCamelCaseAndSingleton()
        {
            var a = JsonOptionsRegistry.CamelCase;
            var b = JsonOptionsRegistry.CamelCase;
            Assert.Same(a, b);
            Assert.Same(JsonNamingPolicy.CamelCase, a.PropertyNamingPolicy);
            Assert.False(a.WriteIndented);
        }

        [Fact]
        public void JsonOptionsRegistry_CamelCaseIndented_IsCamelCaseAndIndented()
        {
            var opts = JsonOptionsRegistry.CamelCaseIndented;
            Assert.Same(JsonNamingPolicy.CamelCase, opts.PropertyNamingPolicy);
            Assert.True(opts.WriteIndented);
        }

        [Fact]
        public void JsonOptionsRegistry_Indented_ProducesNewlines()
        {
            var json = JsonSerializer.Serialize(new { a = 1, b = 2 }, JsonOptionsRegistry.Indented);
            Assert.Contains("\n", json);
        }

        // ---------- RiskLevel ------------------------------------------------

        [Theory]
        [InlineData(RiskLevel.Info,   "INFO")]
        [InlineData(RiskLevel.Low,    "LOW")]
        [InlineData(RiskLevel.Medium, "MEDIUM")]
        [InlineData(RiskLevel.High,   "HIGH")]
        public void RiskLevels_ToTag_RoundTrips(RiskLevel level, string tag)
        {
            Assert.Equal(tag, level.ToTag());
            Assert.Equal(level, RiskLevels.FromTag(tag));
            Assert.Equal(level, RiskLevels.FromTag(tag.ToLowerInvariant()));
        }

        [Theory]
        [InlineData(null,       RiskLevel.Info)]
        [InlineData("",         RiskLevel.Info)]
        [InlineData("garbage",  RiskLevel.Info)]
        public void RiskLevels_FromTag_DefaultsToInfo(string? tag, RiskLevel expected)
        {
            Assert.Equal(expected, RiskLevels.FromTag(tag));
        }

        [Fact]
        public void RiskLevels_AtLeast_OrdersInfoLowMediumHigh()
        {
            Assert.True(RiskLevels.AtLeast(RiskLevel.High,   RiskLevel.Medium));
            Assert.True(RiskLevels.AtLeast(RiskLevel.High,   RiskLevel.High));
            Assert.False(RiskLevels.AtLeast(RiskLevel.Low,   RiskLevel.Medium));
            Assert.True(RiskLevels.AtLeast(RiskLevel.Info,   RiskLevel.Info));
        }

        // ---------- AnalyzerLimits -------------------------------------------

        [Fact]
        public void AnalyzerLimits_AreSane()
        {
            // These are guard rails: limits must be positive and consistent so
            // we don't ship a build with e.g. RegexTimeoutMs = 0 (which would
            // disable our regex DoS protection).
            Assert.True(AnalyzerLimits.MaxSearchTextChars > 0);
            Assert.True(AnalyzerLimits.RegexTimeoutMs > 0);
            Assert.True(AnalyzerLimits.DefaultMaxReadPrefixBytes > 0);
            Assert.True(AnalyzerLimits.DefaultMaxExtractedUrls > 0);
            Assert.True(AnalyzerLimits.DefaultMaxAsciiStrings > 0);
            Assert.True(AnalyzerLimits.DefaultMaxUnicodeStrings > 0);
            Assert.True(AnalyzerLimits.MaxStringEvidenceLength > 0);
            Assert.True(AnalyzerLimits.MaxDistinctRegexMatches > 0);
            Assert.True(AnalyzerLimits.YaraPerRuleTimeoutMs > 0);
            Assert.True(AnalyzerLimits.YaraMaxRuleFiles > 0);
            Assert.True(AnalyzerLimits.YaraMaxHits > 0);
            Assert.True(AnalyzerLimits.ClassifierHttpTimeoutSeconds > 0);
        }
    }
}
