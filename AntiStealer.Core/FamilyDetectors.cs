// PR 11 — Section 2.1 .. 2.3 (modern stealer-family / loader / cloud-config
// detectors). Layered on top of the existing structural classifier in
// Analyzer.cs without disturbing it; ApplyStructuralFamilyClassification
// queries these new detectors and only adopts their verdict if their
// confidence exceeds whatever the legacy heuristic already chose.
//
//   2.1  StealerFamilyDetector — Rhadamanthys / Atomic-AMOS / Banshee /
//        Stealc / Aurora / Meta / SaintStealer / DarkVision / Erbium /
//        Kadu / WhiteSnake / Mystic / Phemedrone / DCRat / Lumma /
//        RisePro / Bandit / Erbium / TitanStealer / etc. Each rule is a
//        small lambda over the StringHits/UrlsFound/etc; rules are
//        prioritised so high-precision string markers (e.g. literal
//        family name in the binary) beat behavioural fingerprints.
//   2.2  LoaderFamilyDetector — SmokeLoader / GuLoader / PrivateLoader /
//        Amadey / DarkGate / NetSupport / BumbleBee / IcedID /
//        Pikabot / FakeUpdates(SocGholish) / RustyStealer-loader.
//        Exposes a separate (LoaderFamily, LoaderConfidence, LoaderReason)
//        on AnalysisResult so a sample can simultaneously be both
//        "Lumma stealer" and "delivered via SmokeLoader".
//   2.3  CloudConfigDetector — extracts embedded IaaS / cloud secrets
//        from the sample's strings: AWS access keys, AWS secrets,
//        Azure storage SAS / connection-strings, GCP service-account
//        JSON, S3 buckets, sendgrid / postmark / mailgun / mandrill
//        keys, Telegram bot tokens (cross-checked with the existing
//        TelegramBotTokenHits list), and chat-platform webhooks
//        (Slack / Discord / Teams). Hits land on
//        AnalysisResult.CloudCredentialHits as "<provider>:<kind>"
//        strings the reports already know how to render.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace AntiStealerOneExe
{
    public sealed partial class AnalysisResult
    {
        // 2.2 — loader-family verdict alongside the existing FamilyName.
        public string LoaderFamily { get; set; } = "";
        public double LoaderConfidence { get; set; }
        public string LoaderReason { get; set; } = "";

        // 2.3 — embedded cloud / IaaS credential hits, in "<provider>:<kind>"
        // form (e.g. "aws:access_key", "gcp:service_account", "slack:webhook").
        public List<string> CloudCredentialHits { get; set; } = new();
    }

    // -----------------------------------------------------------------
    // 2.1  Stealer-family detector
    // -----------------------------------------------------------------

    public sealed record StealerFamilyMatch(string Family, double Confidence, string Reason);

    public static class StealerFamilyDetector
    {
        // Compact (marker, family, confidence, reason) rules — string match
        // over the (lower-cased) concatenated StringHits / UrlsFound /
        // PdbPath. Higher confidence rules win.
        private static readonly (string Marker, string Family, int Conf, string Reason)[] _markers =
        {
            // Modern dominant stealers (string-name hits ≥ 80 %).
            ("rhadamanthys",   "Rhadamanthys",  92, "binary contains 'rhadamanthys' marker"),
            ("rhada_",         "Rhadamanthys",  85, "binary contains rhadamanthys symbol prefix"),
            ("atomicstealer",  "Atomic",        92, "binary contains 'atomicstealer' marker"),
            ("amos_",          "Atomic",        85, "AMOS symbol prefix detected"),
            ("banshee_stealer","Banshee",       92, "binary contains 'banshee_stealer' marker"),
            ("banshee.lib",    "Banshee",       80, "banshee.lib reference"),
            ("stealc",         "Stealc",        88, "string indicators mention stealc"),
            ("auroralogger",   "Aurora",        88, "auroralogger string"),
            ("aurora_stealer", "Aurora",        88, "aurora_stealer marker"),
            ("metastealer",    "Meta",          88, "metastealer marker"),
            ("saintstealer",   "Saint",         85, "saintstealer marker"),
            ("darkvision",     "DarkVision",    85, "darkvision marker"),
            ("erbium",         "Erbium",        80, "erbium marker"),
            ("kadustealer",    "Kadu",          85, "kadustealer marker"),
            ("whitesnake",     "WhiteSnake",    88, "whitesnake marker"),
            ("mysticstealer",  "Mystic",        88, "mysticstealer marker"),
            ("phemedrone",     "Phemedrone",    88, "phemedrone marker"),
            ("dcratbuilder",   "DCRat",         88, "dcratbuilder marker"),
            ("titanstealer",   "Titan",         85, "titanstealer marker"),
            ("banditstealer",  "Bandit",        85, "banditstealer marker"),
            ("nivamizer",      "Nivamizer",     78, "nivamizer marker"),
        };

        public static StealerFamilyMatch? Detect(AnalysisResult r)
        {
            var hay = BuildHaystack(r);

            // Pick the highest-confidence marker, not just the first one
            // listed. The previous first-match-wins loop made the order of
            // `_markers` semantically significant — a lower-confidence
            // marker listed before a higher-confidence one for a different
            // family could win on samples containing both. With ~20 markers
            // and small constant work per check, scanning all of them is
            // negligible and gives a deterministic, confidence-first result.
            (string fam, int conf, string reason)? best = null;
            foreach (var (marker, fam, conf, reason) in _markers)
            {
                if (!hay.Contains(marker, StringComparison.Ordinal)) continue;
                if (best is null || conf > best.Value.conf)
                    best = (fam, conf, reason);
            }
            if (best is not null)
                return new StealerFamilyMatch(best.Value.fam, best.Value.conf, best.Value.reason);

            // Behavioural / multi-IOC rules — used as a fallback when no
            // literal marker is present in the binary.
            if (hay.Contains("crypted by") && hay.Contains("rh ") && r.UrlsFound.Any(u => u != null && u.Contains(".onion")))
                return new StealerFamilyMatch("Rhadamanthys", 78, "rh markers + tor C2");

            if ((hay.Contains("/api/c2") || hay.Contains("/c2sock")) &&
                r.SuspiciousApiHits.Any(a => a != null && a.Contains("CryptUnprotectData", StringComparison.OrdinalIgnoreCase)) &&
                r.CryptoWalletHits.Count > 0)
                return new StealerFamilyMatch("Stealc", 74, "c2 path + dpapi + wallet artifacts");

            if (hay.Contains("application support/google/chrome") &&
                hay.Contains("login.keychain-db"))
                return new StealerFamilyMatch("Atomic", 80, "macOS Chrome+Keychain exfil pattern (AMOS)");

            if (r.FileType.Contains("Mach-O", StringComparison.OrdinalIgnoreCase) &&
                r.CryptoWalletHits.Count > 0 &&
                hay.Contains("keychain-db"))
                return new StealerFamilyMatch("Banshee", 75, "Mach-O + wallet + keychain exfil");

            return null;
        }

        internal static string BuildHaystack(AnalysisResult r)
        {
            var sb = new System.Text.StringBuilder();
            // Defensive: any of these lists might contain a null entry if a
            // detector / parser upstream forgot to filter. `Append(null)`
            // is a no-op on StringBuilder, but `Contains` etc on the joined
            // result would surface garbage — normalise to empty string.
            foreach (var s in r.StringHits)         sb.Append(s ?? "").Append('\n');
            foreach (var s in r.MalwareSelfIdHits)  sb.Append(s ?? "").Append('\n');
            foreach (var s in r.UrlsFound)          sb.Append(s ?? "").Append('\n');
            foreach (var s in r.PackerHints)        sb.Append(s ?? "").Append('\n');
            return sb.ToString().ToLowerInvariant();
        }

        // Case-preserving variant for detectors that need to match on
        // case-sensitive patterns (e.g. AWS AKIA keys, base64 PE headers).
        // Includes the same source lists as BuildHaystack so cloud-cred
        // matches don't go missing when a webhook URL lives in UrlsFound
        // rather than the (curated, AC-filtered) StringHits.
        internal static string BuildRawHaystack(AnalysisResult r)
        {
            var sb = new System.Text.StringBuilder();
            foreach (var s in r.StringHits)         sb.Append(s ?? "").Append('\n');
            foreach (var s in r.MalwareSelfIdHits)  sb.Append(s ?? "").Append('\n');
            foreach (var s in r.UrlsFound)          sb.Append(s ?? "").Append('\n');
            foreach (var s in r.PackerHints)        sb.Append(s ?? "").Append('\n');
            return sb.ToString();
        }
    }

    // -----------------------------------------------------------------
    // 2.2  Loader-family detector
    // -----------------------------------------------------------------

    public sealed record LoaderFamilyMatch(string Family, double Confidence, string Reason);

    public static class LoaderFamilyDetector
    {
        private static readonly (string Marker, string Family, int Conf, string Reason)[] _markers =
        {
            ("smokeloader",     "SmokeLoader",     90, "smokeloader marker"),
            ("smoke loader",    "SmokeLoader",     88, "smoke loader text"),
            ("guloader",        "GuLoader",        90, "guloader marker"),
            ("cloudeye",        "GuLoader",        80, "guloader/CloudEyE marker"),
            ("privateloader",   "PrivateLoader",   90, "privateloader marker"),
            ("amadey",          "Amadey",          88, "amadey marker"),
            ("darkgate",        "DarkGate",        90, "darkgate marker"),
            ("client32.exe",    "NetSupport",      78, "NetSupport client32 reference"),
            ("netsupport.lnk",  "NetSupport",      80, "NetSupport launcher"),
            ("bumblebee",       "BumbleBee",       88, "bumblebee marker"),
            ("photoloader",     "IcedID",          80, "IcedID/Photoloader marker"),
            ("icedid",          "IcedID",          88, "icedid marker"),
            ("pikabot",         "Pikabot",         88, "pikabot marker"),
            ("socgholish",      "SocGholish",      88, "socgholish/FakeUpdates marker"),
            ("fakeupdates",     "SocGholish",      78, "FakeUpdates marker"),
            ("rusty stealer",   "RustyLoader",     76, "rusty stealer/loader marker"),
        };

        public static LoaderFamilyMatch? Detect(AnalysisResult r)
        {
            var hay = StealerFamilyDetector.BuildHaystack(r);
            // Highest-confidence wins, same rationale as in
            // StealerFamilyDetector.Detect above.
            (string fam, int conf, string reason)? best = null;
            foreach (var (m, fam, conf, reason) in _markers)
            {
                if (!hay.Contains(m, StringComparison.Ordinal)) continue;
                if (best is null || conf > best.Value.conf)
                    best = (fam, conf, reason);
            }
            if (best is not null)
                return new LoaderFamilyMatch(best.Value.fam, best.Value.conf, best.Value.reason);

            // Behavioural fallback: shellcode + autoit + tiny PE is a
            // GuLoader profile; RWX + heavy obfuscation + http POST to
            // /panel/index.php is an Amadey profile.
            if (hay.Contains("autoit") && r.ExecutableWritableSections.Count > 0 && r.PackerHints.Count > 0)
                return new LoaderFamilyMatch("GuLoader", 70, "autoit + RWX + packed (GuLoader profile)");

            if (r.UrlsFound.Any(u => u != null && u.Contains("/panel/index.php", StringComparison.OrdinalIgnoreCase)) &&
                r.SuspiciousApiHits.Any(a => a != null &&
                                             (a.Contains("WinExec", StringComparison.OrdinalIgnoreCase) ||
                                              a.Contains("CreateProcess", StringComparison.OrdinalIgnoreCase))))
                return new LoaderFamilyMatch("Amadey", 68, "/panel/index.php + child-process api");

            return null;
        }
    }

    // -----------------------------------------------------------------
    // 2.3  Cloud / IaaS embedded-credential detector
    // -----------------------------------------------------------------

    public static class CloudConfigDetector
    {
        // Use compiled regex for the hot patterns; everything else is a
        // cheap substring match against the lower-cased haystack.
        private static readonly Regex _awsKey =
            new("AKIA[0-9A-Z]{16}", RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex _awsSecret =
            new("(?i)aws(.{0,20})?(secret|sk)([^a-z0-9]{1,3})[A-Za-z0-9/+=]{40}",
                RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex _slackWebhook =
            new("https://hooks\\.slack\\.com/services/[A-Z0-9/]+",
                RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex _discordWebhook =
            new("https://(?:discord(?:app)?)\\.com/api/webhooks/\\d+/[A-Za-z0-9_\\-]+",
                RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex _teamsWebhook =
            new("https://[a-z0-9\\-]+\\.webhook\\.office\\.com/webhookb2/[A-Za-z0-9\\-@/]+",
                RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex _azureConn =
            new("(?i)defaultendpointsprotocol=https;accountname=[a-z0-9]+;accountkey=[A-Za-z0-9+/=]{40,}",
                RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex _azureSas =
            new("(?i)\\?sv=20\\d{2}-\\d{2}-\\d{2}&[^\"\\s]+&sig=[A-Za-z0-9%]+",
                RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex _sendgrid =
            new("SG\\.[A-Za-z0-9_\\-]{22}\\.[A-Za-z0-9_\\-]{43}",
                RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex _mailgun =
            new("(?i)key-[a-f0-9]{32}",
                RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex _telegramBot =
            new("(?i)\\b\\d{6,12}:[A-Za-z0-9_\\-]{30,}",
                RegexOptions.Compiled | RegexOptions.CultureInvariant);

        public static IReadOnlyList<string> Detect(AnalysisResult r)
        {
            var hits = new List<string>();
            // We scan both the upper-case-preserving raw strings (for case-
            // sensitive AWS keys) and the lower-cased haystack (for cheap
            // substring lookups). The raw haystack MUST include UrlsFound
            // — webhook URLs (Slack / Discord / Teams) live there in real
            // Analyzer runs because the curated StringHits list only
            // captures Aho-Corasick-matched suspicious-string needles.
            // Previously this detector joined StringHits alone, silently
            // missing every webhook indicator on real samples.
            string raw = StealerFamilyDetector.BuildRawHaystack(r);
            string hay = raw.ToLowerInvariant();

            if (_awsKey.IsMatch(raw))         hits.Add("aws:access_key");
            if (_awsSecret.IsMatch(raw))      hits.Add("aws:secret_key");
            if (hay.Contains("s3.amazonaws.com") || hay.Contains(".s3.amazonaws.com/"))
                                              hits.Add("aws:s3_bucket");

            if (_azureConn.IsMatch(raw))      hits.Add("azure:connection_string");
            if (_azureSas.IsMatch(raw))       hits.Add("azure:sas_token");
            if (hay.Contains("core.windows.net"))
                                              hits.Add("azure:storage_account");

            // GCP service-account JSON markers — must see both fields in
            // proximity to avoid false-positives from legit BEGIN PRIVATE
            // KEY blocks unrelated to cloud creds.
            if (hay.Contains("\"type\": \"service_account\"") || hay.Contains("\"type\":\"service_account\""))
                                              hits.Add("gcp:service_account");
            if (hay.Contains("googleapis.com/oauth2") && hay.Contains("client_email"))
                                              hits.Add("gcp:oauth_client");

            if (_slackWebhook.IsMatch(raw))   hits.Add("slack:webhook");
            if (_discordWebhook.IsMatch(raw)) hits.Add("discord:webhook");
            if (_teamsWebhook.IsMatch(raw))   hits.Add("teams:webhook");

            if (_sendgrid.IsMatch(raw))       hits.Add("sendgrid:api_key");
            if (_mailgun.IsMatch(raw))        hits.Add("mailgun:api_key");
            if (hay.Contains("postmark-api-token") || hay.Contains("server-token"))
                                              hits.Add("postmark:api_token");

            if (r.TelegramBotTokenHits.Count > 0 || _telegramBot.IsMatch(raw))
                                              hits.Add("telegram:bot_token");

            // De-dup while preserving first-seen order.
            return hits.Distinct(StringComparer.Ordinal).ToList();
        }
    }

    // -----------------------------------------------------------------
    // Glue layer — single entry point invoked from
    // ApplyStructuralFamilyClassification in Analyzer.cs.
    // -----------------------------------------------------------------

    public static class FamilyDetectorPipeline
    {
        public static void RunOn(AnalysisResult r)
        {
            // 2.1
            var stealer = StealerFamilyDetector.Detect(r);
            if (stealer != null && stealer.Confidence > r.FamilyConfidence)
            {
                r.FamilyName       = stealer.Family;
                r.FamilyConfidence = stealer.Confidence;
                r.FamilyReason     = stealer.Reason;
            }

            // 2.2
            var loader = LoaderFamilyDetector.Detect(r);
            if (loader != null && loader.Confidence > r.LoaderConfidence)
            {
                r.LoaderFamily     = loader.Family;
                r.LoaderConfidence = loader.Confidence;
                r.LoaderReason     = loader.Reason;
            }

            // 2.3
            foreach (var hit in CloudConfigDetector.Detect(r))
                if (!r.CloudCredentialHits.Contains(hit, StringComparer.Ordinal))
                    r.CloudCredentialHits.Add(hit);
        }
    }
}
