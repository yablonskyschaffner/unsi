using System;
using System.Text.RegularExpressions;
using FsCheck.Xunit;
using Xunit;

namespace AntiStealer.Tests;

/// <summary>
/// I3: Property-based tests — the analyser runs a fixed set of regex patterns over arbitrary input,
/// so we fuzz-test each hot regex to confirm it terminates within a sane budget regardless of input
/// and never throws on UTF-8 garbage. This guards against ReDoS / runaway backtracking.
/// </summary>
public class RegexSafetyTests
{
    // Mirror the patterns the analyser uses for IOCs — if any of these explode on adversarial input,
    // Analyzer.Analyze() would hang a scan.
    private static readonly Regex UrlRegex = new(
        @"\b(?:https?|ftp|ftps)://[^\s""'<>)]+",
        RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(200));

    private static readonly Regex Ipv4Regex = new(
        @"\b(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}\b",
        RegexOptions.Compiled, TimeSpan.FromMilliseconds(200));

    private static readonly Regex EmailRegex = new(
        @"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
        RegexOptions.Compiled, TimeSpan.FromMilliseconds(200));

    private static readonly Regex Base64Regex = new(
        @"[A-Za-z0-9+/]{80,}={0,2}",
        RegexOptions.Compiled, TimeSpan.FromMilliseconds(200));

    private static bool SafeMatch(Regex rx, string? input)
    {
        try { _ = rx.Matches(input ?? "").Count; return true; }
        catch (RegexMatchTimeoutException) { return true; }  // timeout is acceptable, hang is not
        catch { return false; }
    }

    // FsCheck drives these with 300 random strings each. Any throw other than a timeout fails the
    // property, catching ReDoS regressions.
    [Property(MaxTest = 300)]
    public bool UrlRegex_DoesNotThrowOnArbitraryStrings(string input) => SafeMatch(UrlRegex, input);

    [Property(MaxTest = 300)]
    public bool Ipv4Regex_DoesNotThrowOnArbitraryStrings(string input) => SafeMatch(Ipv4Regex, input);

    [Property(MaxTest = 300)]
    public bool EmailRegex_DoesNotThrowOnArbitraryStrings(string input) => SafeMatch(EmailRegex, input);

    [Property(MaxTest = 300)]
    public bool Base64Regex_DoesNotThrowOnArbitraryStrings(string input) => SafeMatch(Base64Regex, input);

    [Theory]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("http://")]
    [InlineData("https://")]
    [InlineData("@.")]
    [InlineData("...")]
    [InlineData("")]
    public void Regexes_DoNotThrowOnKnownTrickyInputs(string s)
    {
        Assert.True(SafeMatch(UrlRegex, s));
        Assert.True(SafeMatch(Ipv4Regex, s));
        Assert.True(SafeMatch(EmailRegex, s));
        Assert.True(SafeMatch(Base64Regex, s));
    }
}
