// Section 22.8 — RiskLevel enum + helpers.
//
// The string "HIGH" / "MEDIUM" / "LOW" / "INFO" tags appear in the JSON / SARIF
// / STIX / HTML / PDF reports already, so we cannot rename them without breaking
// downstream consumers. This enum is purely *additive*: the on-the-wire
// representation stays the same; new code can prefer the strongly-typed enum
// and round-trip through ToTag() / FromTag().
namespace AntiStealerOneExe
{
    public enum RiskLevel
    {
        Info,
        Low,
        Medium,
        High,
    }

    public static class RiskLevels
    {
        // Canonical string forms (uppercase) used throughout existing reports.
        public const string TagInfo   = "INFO";
        public const string TagLow    = "LOW";
        public const string TagMedium = "MEDIUM";
        public const string TagHigh   = "HIGH";

        public static string ToTag(this RiskLevel level) => level switch
        {
            RiskLevel.High   => TagHigh,
            RiskLevel.Medium => TagMedium,
            RiskLevel.Low    => TagLow,
            _                => TagInfo,
        };

        public static RiskLevel FromTag(string? tag)
        {
            if (string.IsNullOrEmpty(tag)) return RiskLevel.Info;
            if (tag.Equals(TagHigh,   System.StringComparison.OrdinalIgnoreCase)) return RiskLevel.High;
            if (tag.Equals(TagMedium, System.StringComparison.OrdinalIgnoreCase)) return RiskLevel.Medium;
            if (tag.Equals(TagLow,    System.StringComparison.OrdinalIgnoreCase)) return RiskLevel.Low;
            return RiskLevel.Info;
        }

        // True if a is at least as severe as b.
        public static bool AtLeast(RiskLevel a, RiskLevel b) => (int)a >= (int)b;
    }
}
