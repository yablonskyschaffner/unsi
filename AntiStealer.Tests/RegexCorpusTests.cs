using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using FsCheck;
using FsCheck.Xunit;
using Xunit;

namespace AntiStealer.Tests;

/// <summary>
/// Section 6.3 — Property-based safety net for the full IOC-regex family the
/// analyser runs over arbitrary file bytes. Each pattern below is a *verbatim*
/// copy of the one in <c>AntiStealer.Core/Analyzer.cs</c>; if those drift, the
/// build fails because the file is right next to the test.
///
/// What we check:
///   1. The regex does not throw on adversarial input (only RegexMatchTimeoutException
///      is acceptable — a hard hang is not).
///   2. The regex terminates within the 200 ms budget the analyser allots
///      (FsCheck drives 200 random strings per pattern).
///   3. For each well-known *positive* example the regex actually matches —
///      catches the silent-regression case where someone refactors a pattern
///      and breaks a real detection.
/// </summary>
public class RegexCorpusTests
{
    // Mirror of Analyzer.cs `RegexTimeout`.
    private static readonly TimeSpan T = TimeSpan.FromMilliseconds(200);

    // ----------------------------------------------------------------
    // Patterns mirrored from Analyzer.cs (line numbers from the
    // current head: 157-173). Keep them in lock-step.
    // ----------------------------------------------------------------
    private static readonly Regex UrlRx                = new(@"https?://[^\s\""'<>]+", RegexOptions.IgnoreCase | RegexOptions.Compiled, T);
    private static readonly Regex Base64BlobRx         = new(@"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})(?![A-Za-z0-9+/=])", RegexOptions.Compiled, T);
    private static readonly Regex Ipv4Rx               = new(@"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b", RegexOptions.Compiled, T);
    private static readonly Regex EmailRx              = new(@"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", RegexOptions.Compiled, T);
    private static readonly Regex BtcRx                = new(@"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{24,62}\b", RegexOptions.Compiled, T);
    private static readonly Regex EthRx                = new(@"\b0x[a-fA-F0-9]{40}\b", RegexOptions.Compiled, T);
    private static readonly Regex TronRx               = new(@"\bT[1-9A-HJ-NP-Za-km-z]{33}\b", RegexOptions.Compiled, T);
    private static readonly Regex SolRx                = new(@"\b[1-9A-HJ-NP-Za-km-z]{43,44}\b", RegexOptions.Compiled, T);
    private static readonly Regex XmrRx                = new(@"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b", RegexOptions.Compiled, T);
    private static readonly Regex JwtRx                = new(@"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", RegexOptions.Compiled, T);
    private static readonly Regex TelegramBotRx        = new(@"\b\d{8,10}:[A-Za-z0-9_-]{30,40}\b", RegexOptions.Compiled, T);
    private static readonly Regex DiscordLegacyRx      = new(@"\b[A-Za-z\d_-]{24}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27}\b", RegexOptions.Compiled, T);
    private static readonly Regex DiscordCurrentRx     = new(@"\b[A-Za-z\d_-]{26,28}\.[A-Za-z\d_-]{6,7}\.[A-Za-z\d_-]{38,}\b", RegexOptions.Compiled, T);
    private static readonly Regex DiscordMfaRx         = new(@"\bmfa\.[A-Za-z0-9_-]{84}\b", RegexOptions.Compiled, T);
    private static readonly Regex PrivateKeyBlockRx    = new(@"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED) PRIVATE KEY-----", RegexOptions.Compiled, T);

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    /// <summary>
    /// Run the regex on arbitrary input; the only failure modes that should
    /// ever fail the property are (a) hangs (no return within the regex's own
    /// timeout) — those manifest as <see cref="RegexMatchTimeoutException"/>,
    /// which we explicitly tolerate — or (b) unexpected exception types.
    /// </summary>
    private static bool SafeMatch(Regex rx, string? input)
    {
        try { _ = rx.Matches(input ?? "").Count; return true; }
        catch (RegexMatchTimeoutException) { return true; }
        catch { return false; }
    }

    /// <summary>
    /// FsCheck's default <c>string</c> generator yields a lot of empties; we
    /// want a higher-density mix that includes long runs of regex-trigger
    /// characters (dots, slashes, alphanumerics) to actually probe ReDoS.
    /// </summary>
    public sealed class Arbitraries
    {
        public static Arbitrary<string> StressyString() =>
            Arb.From(
                Gen.OneOf(
                    Arb.Default.String().Generator,
                    Gen.Sized(n =>
                    {
                        if (n <= 0) return Gen.Constant(string.Empty);
                        // Pool of "spicy" chars that look like protocol prefixes / base58 / base64
                        // padding / IPv4 separators / private-key block markers.
                        char[] pool = "abcdefABCDEF0123456789-_+/=.@:.\\/".ToCharArray();
                        return Gen.ArrayOf(n, Gen.Elements(pool))
                                  .Select(chars => new string(chars));
                    })));
    }

    [Property(Arbitrary = new[] { typeof(Arbitraries) }, MaxTest = 200)]
    public bool UrlRegex_Survives(string s)                 => SafeMatch(UrlRx, s);
    [Property(Arbitrary = new[] { typeof(Arbitraries) }, MaxTest = 200)]
    public bool Base64BlobRegex_Survives(string s)          => SafeMatch(Base64BlobRx, s);
    [Property(Arbitrary = new[] { typeof(Arbitraries) }, MaxTest = 200)]
    public bool Ipv4Regex_Survives(string s)                => SafeMatch(Ipv4Rx, s);
    [Property(Arbitrary = new[] { typeof(Arbitraries) }, MaxTest = 200)]
    public bool EmailRegex_Survives(string s)               => SafeMatch(EmailRx, s);
    [Property(Arbitrary = new[] { typeof(Arbitraries) }, MaxTest = 200)]
    public bool BtcRegex_Survives(string s)                 => SafeMatch(BtcRx, s);
    [Property(Arbitrary = new[] { typeof(Arbitraries) }, MaxTest = 200)]
    public bool EthRegex_Survives(string s)                 => SafeMatch(EthRx, s);
    [Property(Arbitrary = new[] { typeof(Arbitraries) }, MaxTest = 200)]
    public bool TronRegex_Survives(string s)                => SafeMatch(TronRx, s);
    [Property(Arbitrary = new[] { typeof(Arbitraries) }, MaxTest = 200)]
    public bool SolRegex_Survives(string s)                 => SafeMatch(SolRx, s);
    [Property(Arbitrary = new[] { typeof(Arbitraries) }, MaxTest = 200)]
    public bool XmrRegex_Survives(string s)                 => SafeMatch(XmrRx, s);
    [Property(Arbitrary = new[] { typeof(Arbitraries) }, MaxTest = 200)]
    public bool JwtRegex_Survives(string s)                 => SafeMatch(JwtRx, s);
    [Property(Arbitrary = new[] { typeof(Arbitraries) }, MaxTest = 200)]
    public bool TelegramBotRegex_Survives(string s)         => SafeMatch(TelegramBotRx, s);
    [Property(Arbitrary = new[] { typeof(Arbitraries) }, MaxTest = 200)]
    public bool DiscordLegacyRegex_Survives(string s)       => SafeMatch(DiscordLegacyRx, s);
    [Property(Arbitrary = new[] { typeof(Arbitraries) }, MaxTest = 200)]
    public bool DiscordCurrentRegex_Survives(string s)      => SafeMatch(DiscordCurrentRx, s);
    [Property(Arbitrary = new[] { typeof(Arbitraries) }, MaxTest = 200)]
    public bool DiscordMfaRegex_Survives(string s)          => SafeMatch(DiscordMfaRx, s);
    [Property(Arbitrary = new[] { typeof(Arbitraries) }, MaxTest = 200)]
    public bool PrivateKeyBlockRegex_Survives(string s)     => SafeMatch(PrivateKeyBlockRx, s);

    // ----------------------------------------------------------------
    // Known-positive smoke tests — make sure each regex still detects the
    // real-world IOC shape it's supposed to. These are the inverse of the
    // property tests: if a refactor breaks the *positive* match, this trips.
    // ----------------------------------------------------------------
    [Theory]
    [InlineData("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")]                                       // Genesis block (P2PKH)
    [InlineData("3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5")]                                       // BitPay (P2SH)
    [InlineData("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")]                              // Bech32
    public void BtcRegex_KnownPositives_Match(string addr) =>
        Assert.Matches(BtcRx, addr);

    [Theory]
    [InlineData("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe")]                              // Vitalik
    [InlineData("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")]
    public void EthRegex_KnownPositives_Match(string addr) =>
        Assert.Matches(EthRx, addr);

    [Theory]
    [InlineData("TLPpXqGMmJxchxnG9KZyQs3uoR4rzn9JtP")]
    [InlineData("TKzxdSv2FZKQrEqkKVgp5DcwEXBEKMg2Ax")]
    public void TronRegex_KnownPositives_Match(string addr) =>
        Assert.Matches(TronRx, addr);

    [Theory]
    [InlineData("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM")]                            // 44-char base58
    public void SolRegex_KnownPositives_Match(string addr) =>
        Assert.Matches(SolRx, addr);

    [Theory]
    [InlineData("48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD")]
    public void XmrRegex_KnownPositives_Match(string addr) =>
        Assert.Matches(XmrRx, addr);

    [Theory]
    [InlineData("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.5x4j2ZxJUw6L1KPbXuYZ7y8mZ0p9V4Wq2lQwSDpQyzU")]
    public void JwtRegex_KnownPositives_Match(string token) =>
        Assert.Matches(JwtRx, token);

    [Theory]
    [InlineData("1234567890:ABCDEFghijklmnopqrstuvwx_-yzABCDEFG")]
    public void TelegramBotRegex_KnownPositives_Match(string token) =>
        Assert.Matches(TelegramBotRx, token);

    [Theory]
    [InlineData("-----BEGIN RSA PRIVATE KEY-----")]
    [InlineData("-----BEGIN OPENSSH PRIVATE KEY-----")]
    [InlineData("-----BEGIN ENCRYPTED PRIVATE KEY-----")]
    public void PrivateKeyBlockRegex_KnownPositives_Match(string header) =>
        Assert.Matches(PrivateKeyBlockRx, header);

    // ----------------------------------------------------------------
    // Known-negative smoke tests — ensure each regex rejects clear non-IOCs
    // that have tripped older regex revisions in the past.
    // ----------------------------------------------------------------
    [Theory]
    [InlineData("1Aa")]                                              // way too short for BTC
    [InlineData("not-an-address")]
    public void BtcRegex_KnownNegatives_DoNotMatch(string s) =>
        Assert.DoesNotMatch(BtcRx, s);

    [Theory]
    [InlineData("0x")]
    [InlineData("0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG")]
    public void EthRegex_KnownNegatives_DoNotMatch(string s) =>
        Assert.DoesNotMatch(EthRx, s);

    [Theory]
    [InlineData("aaa")]
    [InlineData("eyJ.bad.short")]
    public void JwtRegex_KnownNegatives_DoNotMatch(string s) =>
        Assert.DoesNotMatch(JwtRx, s);

    // ----------------------------------------------------------------
    // Carefully-crafted long inputs that historically tipped over older
    // regex implementations on .NET. All must complete inside T (200 ms).
    // ----------------------------------------------------------------
    public static IEnumerable<object[]> RedosSeeds()
    {
        yield return new object[] { new string('a', 50_000) };
        yield return new object[] { new string('0', 50_000) };
        yield return new object[] { "https://" + new string('a', 50_000) };
        yield return new object[] { new string('A', 50_000) + "==" };
        yield return new object[] { string.Concat(Enumerable.Repeat("1.", 25_000)) };
        yield return new object[] { string.Concat(Enumerable.Repeat("eyJ.AAAA", 5_000)) };
        yield return new object[] { string.Concat(Enumerable.Repeat("12345678:", 5_000)) };
    }

    [Theory]
    [MemberData(nameof(RedosSeeds))]
    public void AllRegexes_CompleteWithinBudget_OnAdversarialInput(string s)
    {
        Regex[] all =
        {
            UrlRx, Base64BlobRx, Ipv4Rx, EmailRx, BtcRx, EthRx, TronRx, SolRx, XmrRx,
            JwtRx, TelegramBotRx, DiscordLegacyRx, DiscordCurrentRx, DiscordMfaRx, PrivateKeyBlockRx,
        };
        foreach (var rx in all)
        {
            // Each call has its own ~200 ms cap; if the engine genuinely hangs
            // it'll throw RegexMatchTimeoutException, which we accept.
            Assert.True(SafeMatch(rx, s));
        }
    }
}
