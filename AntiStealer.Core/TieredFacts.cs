// PR 15 — Section 4 — Stage B16: tiered facts.
//
// Splits the heap of "string matched" findings on AnalysisResult
// into four explicit evidence tiers so reports and rule writers
// can distinguish bare keyword hits from full behavior chains.
//
//   Weak     — single noisy keyword: "chrome", "wallet", "token".
//   Medium   — full credential path (e.g. r"...\Login Data") or a
//              file open against it. Indicates intent.
//   Strong   — credential path + collection capability (SQLite,
//              CryptUnprotectData, ZIP packaging). Indicates
//              capability.
//   Critical — path + collection + exfil sink (Telegram bot URL,
//              Discord webhook, paste site, ngrok, …). Indicates
//              a working stealer chain.
//
// The classifier is intentionally read-only: it does not change
// the score. It produces a sidecar `r.TieredFacts` list that the
// UI / CSV / JSON reports surface so an operator can answer
// "what evidence does this score sit on?" at a glance.
//
// Calling `TieredFactClassifier.Classify(r)` is idempotent and
// safe to call multiple times — duplicates are dropped.

using System;
using System.Collections.Generic;
using System.Linq;

namespace AntiStealerOneExe
{
    public enum FactStrength
    {
        Weak     = 0,
        Medium   = 1,
        Strong   = 2,
        Critical = 3,
    }

    public sealed record TieredFact(FactStrength Strength, string Category, string Evidence);

    public sealed partial class AnalysisResult
    {
        // B16 — tiered evidence sidecar. Populated by
        // TieredFactClassifier.Classify(this) after analysis.
        public List<TieredFact> TieredFacts { get; set; } = new();
    }

    public static class TieredFactClassifier
    {
        // ----- Keyword corpora ----------------------------------------

        private static readonly string[] WeakBrowserWords =
        {
            "chrome", "firefox", "edge", "brave", "opera", "vivaldi",
            "yandex", "librewolf",
        };
        private static readonly string[] WeakWalletWords =
        {
            "wallet", "metamask", "phantom", "exodus", "atomic", "electrum",
            "trust wallet", "bitcoin", "ethereum", "monero",
        };
        private static readonly string[] WeakSecretWords =
        {
            "password", "token", "passphrase", "mnemonic", "private key",
            "api key",
        };

        // Medium — full paths / file names that name a specific
        // credential target.  These are rarely a coincidence on
        // legitimate software.
        private static readonly (string Needle, string Category)[] MediumPaths =
        {
            (@"\Google\Chrome\User Data",        "browser.chrome"),
            (@"\Microsoft\Edge\User Data",       "browser.edge"),
            (@"\BraveSoftware\Brave-Browser",    "browser.brave"),
            (@"\Yandex\YandexBrowser",           "browser.yandex"),
            (@"\Mozilla\Firefox\Profiles",       "browser.firefox"),
            (@"Login Data",                      "browser.logindb"),
            (@"\Cookies",                        "browser.cookies"),
            (@"\Web Data",                       "browser.webdata"),
            (@"\Local State",                    "browser.localstate"),
            (@"\discord\Local Storage",          "discord.leveldb"),
            (@"\Telegram Desktop\tdata",         "telegram.tdata"),
            (@"\Exodus\exodus.wallet",           "wallet.exodus"),
            (@"\Electrum\wallets",               "wallet.electrum"),
            (@"\atomic\Local Storage",           "wallet.atomic"),
            (@"wallet.dat",                      "wallet.bitcoin"),
            (@".aws/credentials",                "cloud.aws"),
            (@"\.aws\credentials",               "cloud.aws"),
            (@".ssh/id_rsa",                     "cloud.ssh"),
            (@"\.ssh\id_rsa",                    "cloud.ssh"),
            (@".env",                            "cloud.env"),
            (@"\kubeconfig",                     "cloud.kube"),
            (@".dockercfg",                      "cloud.docker"),
            (@"\Steam\config\loginusers.vdf",    "messenger.steam"),
        };

        // Strong — collection / decryption capability that turns
        // intent into action.
        private static readonly string[] CollectionCapabilities =
        {
            "SQLite format 3", "sqlite3_open", "CryptUnprotectData",
            "DPAPI", "os_crypt", "BCryptDecrypt", "AES_decrypt",
            "ZipArchive", "Compression.GZip",
        };

        // Critical — exfil sink that closes the chain.
        private static readonly string[] ExfilSinkSubstrings =
        {
            "api.telegram.org/bot",
            "discord.com/api/webhooks",
            "discordapp.com/api/webhooks",
            "pastebin.com/raw",
            "anonfiles.com",
            "transfer.sh",
            "gofile.io",
            "ngrok.io",
            "trycloudflare.com",
        };

        // -----------------------------------------------------------------

        /// <summary>
        /// Walk the result's signals and emit tiered facts.  Idempotent —
        /// calling it twice does not double-count.
        /// </summary>
        public static void Classify(AnalysisResult r)
        {
            if (r == null) return;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var f in r.TieredFacts)
                seen.Add(f.Strength + "|" + f.Category + "|" + f.Evidence);

            void Emit(FactStrength s, string cat, string ev)
            {
                if (string.IsNullOrEmpty(ev)) return;
                var key = s + "|" + cat + "|" + ev;
                if (!seen.Add(key)) return;
                if (r.TieredFacts.Count < 128)
                    r.TieredFacts.Add(new TieredFact(s, cat, ev));
            }

            var hits   = r.StringHits ?? new List<string>();
            var urls   = r.UrlsFound ?? new List<string>();
            var hitsLow = hits.Select(h => h ?? "")
                              .Select(h => h.ToLowerInvariant())
                              .ToList();

            // Compute capability presence once.
            bool hasCollection = hits.Any(h => h != null &&
                CollectionCapabilities.Any(c =>
                    h.Contains(c, StringComparison.OrdinalIgnoreCase)));
            bool hasExfilSink =
                (r.TelegramExfilEndpoints?.Count ?? 0) > 0 ||
                (r.DiscordTokenHits?.Count ?? 0)        > 0 ||
                urls.Any(u => u != null &&
                    ExfilSinkSubstrings.Any(es =>
                        u.Contains(es, StringComparison.OrdinalIgnoreCase)));

            // ---- Weak: bare keyword hits ---------------------------------
            foreach (var w in WeakBrowserWords)
                if (hitsLow.Any(h => h.Contains(w, StringComparison.Ordinal)))
                    Emit(FactStrength.Weak, "keyword.browser", w);
            foreach (var w in WeakWalletWords)
                if (hitsLow.Any(h => h.Contains(w, StringComparison.Ordinal)))
                    Emit(FactStrength.Weak, "keyword.wallet", w);
            foreach (var w in WeakSecretWords)
                if (hitsLow.Any(h => h.Contains(w, StringComparison.Ordinal)))
                    Emit(FactStrength.Weak, "keyword.secret", w);

            // ---- Medium / Strong / Critical: path-anchored ---------------
            bool anyMediumPath = false;
            foreach (var (needle, cat) in MediumPaths)
            {
                var sample = hits.FirstOrDefault(h => h != null &&
                    h.Contains(needle, StringComparison.OrdinalIgnoreCase));
                if (sample == null) continue;
                anyMediumPath = true;

                if (hasCollection && hasExfilSink)
                {
                    Emit(FactStrength.Critical, cat,
                         "path+collection+exfil: " + Trim(sample));
                }
                else if (hasCollection)
                {
                    Emit(FactStrength.Strong, cat,
                         "path+collection: " + Trim(sample));
                }
                else
                {
                    Emit(FactStrength.Medium, cat, Trim(sample));
                }
            }

            // ---- PowerShell encoded-cradle special case ------------------
            bool hasEncodedPs = hits.Any(h => h != null && (
                h.Contains("-EncodedCommand", StringComparison.OrdinalIgnoreCase) ||
                h.Contains("-enc ",            StringComparison.OrdinalIgnoreCase) ||
                h.Contains("FromBase64String", StringComparison.OrdinalIgnoreCase)));
            bool hasPsExecVector = hits.Any(h => h != null && (
                h.Contains("DownloadString",   StringComparison.OrdinalIgnoreCase) ||
                h.Contains("Invoke-Expression",StringComparison.OrdinalIgnoreCase) ||
                h.Contains("iex ",             StringComparison.OrdinalIgnoreCase)));
            if (hasEncodedPs && hasPsExecVector && urls.Count > 0)
                Emit(FactStrength.Critical, "execution.ps_cradle",
                     "encoded ps + downloadstring + url");
            else if (hasEncodedPs && hasPsExecVector)
                Emit(FactStrength.Strong, "execution.ps_cradle",
                     "encoded ps + downloadstring");
            else if (hasEncodedPs)
                Emit(FactStrength.Medium, "execution.ps_encoded",
                     "encoded ps command");

            // ---- ClickFix / fake-CAPTCHA --------------------------------
            bool clickfix = hits.Any(h => h != null &&
                h.Contains("verify you are human", StringComparison.OrdinalIgnoreCase) ||
                h != null && h.Contains("captcha", StringComparison.OrdinalIgnoreCase));
            bool winRPaste = hits.Any(h => h != null &&
                (h.Contains("Win+R",  StringComparison.OrdinalIgnoreCase) ||
                 h.Contains("Ctrl+V", StringComparison.OrdinalIgnoreCase)));
            if (clickfix && winRPaste)
                Emit(FactStrength.Strong, "social.clickfix",
                     "captcha + Win+R/Ctrl+V");
            else if (clickfix)
                Emit(FactStrength.Weak, "social.captcha", "captcha-only");

            // ---- Floors already established by Score() are Critical -----
            if (r.AppliedFloors != null)
                foreach (var floor in r.AppliedFloors)
                    Emit(FactStrength.Critical, "floor", floor);

            // ---- Bare URL on its own is Weak ----------------------------
            if (urls.Count >= 1 && !hasExfilSink && !anyMediumPath)
                Emit(FactStrength.Weak, "network.url", urls[0]);
        }

        private static string Trim(string s) =>
            s == null
                ? ""
                : s.Length > 96 ? s.Substring(0, 96) + "…" : s;

        // ---- Convenience accessors used by the UI / CSV exporter ------

        public static int Count(AnalysisResult r, FactStrength s) =>
            r?.TieredFacts?.Count(f => f.Strength == s) ?? 0;

        public static IEnumerable<TieredFact> Critical(AnalysisResult r) =>
            r?.TieredFacts?.Where(f => f.Strength == FactStrength.Critical)
                ?? Enumerable.Empty<TieredFact>();
    }
}
