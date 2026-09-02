// BB27: browser-JS credential-stealer detector.
//
// Why this is a separate module
// -----------------------------
// The existing BB/C* modules target PE binaries (imports, Rich header, imphash,
// .rsrc entropy, …). Increasingly stealers ship as pure browser JavaScript —
// either pasted into the DevTools console of a target site (e.g. a Russian SAMP
// panel) or delivered via a malicious extension. Example sample
// `FINAL_CREDENTIALS_MONITOR` (sssssa.vercel.app/api/creds) scrapes
// `input[type="password"]` and POSTs JSON `{nick, password, serverId}` —
// a perfectly canonical credential scraper.
//
// The detector looks for three independent behaviors; 2-of-3 triggers
// escalate the sample to HIGH via the decisive-stealer floor.
//
//   1. cred-scraping DOM pattern  (reading password/nick inputs)
//   2. cred-POST payload pattern  (JSON.stringify with credential-field names)
//   3. hook-installation pattern  (MutationObserver / addEventListener for
//                                  submit|click|change wired to a password
//                                  field selector)
//
// Hosting domains (vercel.app / netlify.app / pages.dev / workers.dev / …) are
// **deliberately not** in any "bad" list — they are legitimate free hosts. The
// combination of cred-scraping JS + an outbound POST is what's decisive, not
// the destination URL.

namespace AntiStealerOneExe
{
    public sealed partial class AnalysisResult
    {
        // BB27 — browser-JS / web-form credential stealer signals.
        public List<string> JsCredScraperHits   { get; set; } = new();
        public List<string> JsCredPostHits      { get; set; } = new();
        public List<string> JsFormHookHits      { get; set; } = new();
        public List<string> JsStealerSelfIdHits { get; set; } = new();
    }

    public static partial class Analyzer
    {
        // JS/TS/JSX/HTML-likely file by extension. We don't gate on this —
        // stealers often come in .txt or unknown — but when the file is plainly
        // a script we can apply tighter heuristics without worrying about
        // false positives against random binaries that happen to contain
        // "password" substrings.
        private static bool LooksLikeScript(AnalysisResult r)
        {
            if (string.IsNullOrEmpty(r.FilePath)) return false;
            var ext = Path.GetExtension(r.FilePath).ToLowerInvariant();
            return ext is ".js" or ".mjs" or ".cjs" or ".ts" or ".tsx" or ".jsx"
                       or ".html" or ".htm" or ".vue" or ".svelte" or ".php";
        }

        // ----------------------------------------------------------------
        // (1) Cred-scraping DOM pattern
        // ----------------------------------------------------------------
        private static readonly string[] JsCredScraperNeedles =
        {
            // Direct password-field selectors.
            "input[type=\"password\"]",
            "input[type='password']",
            "input[type=password]",
            "document.querySelector('input[type=\"password\"]')",
            "querySelectorAll('input[type=\"password\"]')",
            "getElementsByName(\"password\")",
            "getElementById(\"password\")",
            "getElementById('password')",

            // Common JS form-grabber idioms.
            ".value // password", "pwd.value", "password.value", "passwordField",
            "loginField", "usernameField", ".login-form__", ".password-input",
            "name=\"password\"", "name='password'",

            // Attribute-based scrapers seen in SA:MP / MTA / browser-game panels.
            "login-head__username", "login-form__button",
            "type==\"password\"", "type === \"password\"", "type === 'password'",
        };

        // ----------------------------------------------------------------
        // (2) Cred-POST payload pattern — JSON.stringify with ≥2 credential
        //     field names. Reject if only one; single-field is too broad.
        // ----------------------------------------------------------------
        private static readonly string[] CredentialJsonFields =
        {
            "nick", "username", "login", "email", "mail",
            "password", "pwd", "passwd", "pass",
            "token", "cookie", "session", "sessionid",
            "serverid", "server_id", "otp", "2fa", "mfa",
        };

        // ----------------------------------------------------------------
        // (3) Form-hook pattern
        // ----------------------------------------------------------------
        private static readonly string[] JsFormHookNeedles =
        {
            "new MutationObserver",
            "MutationObserver(",
            "addEventListener('submit'",
            "addEventListener(\"submit\"",
            "addEventListener('click'",
            "addEventListener(\"click\"",
            "addEventListener('change'",
            "addEventListener(\"change\"",
            "addEventListener('input'",
            "addEventListener(\"input\"",
            "addEventListener('keydown'",
            "addEventListener(\"keydown\"",
            "addEventListener('keyup'",
            "addEventListener(\"keyup\"",
            "onbeforeunload",
            "form.submit()",
        };

        // ----------------------------------------------------------------
        // (4) Self-ID keywords specific to JS stealers
        // ----------------------------------------------------------------
        private static readonly string[] JsSelfIdNeedles =
        {
            "CRED_MONITOR", "CREDENTIALS_MONITOR", "CRED_GRABBER",
            "passwordStealer", "passwordGrabber", "passgrab",
            "credStealer", "credGrabber", "credmon",
            "FINAL_CREDENTIALS", "FINAL_CRED",
            "captureServerId", "captureCreds", "captureLogin",
            "sendCreds", "sendCredentials", "sendPassword", "sendPwd",
            "grabPassword", "grabCredentials", "grabLogin",
            "loginStealer", "loginGrabber",
            "formgrabber", "form_grabber", "form-grabber",
            "keylogger", "keyLogger", "keystrokeLogger",
            "stealer", // generic but surfaces self-named stuff
            "__stealer", "window.__CRED", "window.__GRAB",
            "trySend(", "sendNow(",                   // typical names
            "exfiltrate", "exfil(",
        };

        internal static void DetectBrowserJsStealer(AnalysisResult r, string analysisText)
        {
            // 1. scraper
            foreach (var n in JsCredScraperNeedles)
                if (analysisText.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0)
                    r.JsCredScraperHits.Add(n);

            // 2. post-payload — JSON.stringify(...) with ≥2 credential fields within 400 chars.
            int idx = 0;
            while (true)
            {
                int k = analysisText.IndexOf("JSON.stringify", idx, StringComparison.OrdinalIgnoreCase);
                if (k < 0) break;
                int end = Math.Min(analysisText.Length, k + 400);
                string window = analysisText.Substring(k, end - k);
                int fieldHits = 0;
                var matched = new List<string>();
                foreach (var f in CredentialJsonFields)
                {
                    // Match "<field>:" or "\"<field>\":" — avoid coincidental in-prose matches.
                    if (window.IndexOf("\"" + f + "\"", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        window.IndexOf("'" + f + "'", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        System.Text.RegularExpressions.Regex.IsMatch(window, "\\b" + System.Text.RegularExpressions.Regex.Escape(f) + "\\s*:",
                            System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                    {
                        fieldHits++;
                        matched.Add(f);
                    }
                }
                if (fieldHits >= 2)
                    r.JsCredPostHits.Add($"JSON.stringify with credential fields: {string.Join(",", matched)}");
                idx = k + 14;
            }

            // Also look for fetch(...) / XMLHttpRequest + body containing credential fields.
            if ((analysisText.IndexOf("XMLHttpRequest", StringComparison.Ordinal) >= 0 ||
                 analysisText.IndexOf("xhr.open",       StringComparison.OrdinalIgnoreCase) >= 0 ||
                 analysisText.IndexOf("fetch(",         StringComparison.OrdinalIgnoreCase) >= 0 ||
                 analysisText.IndexOf("navigator.sendBeacon", StringComparison.OrdinalIgnoreCase) >= 0) &&
                CountCredentialFieldTokens(analysisText) >= 2 &&
                r.JsCredPostHits.Count == 0)
            {
                r.JsCredPostHits.Add("XHR/fetch/sendBeacon near credential fields");
            }

            // 3. hooks
            foreach (var n in JsFormHookNeedles)
                if (analysisText.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0)
                    r.JsFormHookHits.Add(n);

            // 4. self-id
            foreach (var n in JsSelfIdNeedles)
                if (analysisText.IndexOf(n, StringComparison.Ordinal) >= 0)   // case-sensitive for developer strings
                    r.JsStealerSelfIdHits.Add(n);

            // Tighten: if the file extension is a known script AND we have at least one
            // scraper + one POST hit, mirror it into MalwareSelfIdHits + TelegramExfilEndpoints'
            // adjacent counters so the decisive-stealer floor can fire.
            bool scriptContext = LooksLikeScript(r) ||
                                 analysisText.IndexOf("<script",  StringComparison.OrdinalIgnoreCase) >= 0 ||
                                 analysisText.IndexOf("document.", StringComparison.Ordinal) >= 0 ||
                                 analysisText.IndexOf("window.",   StringComparison.Ordinal) >= 0;
            if (scriptContext && r.JsCredScraperHits.Count >= 1 && r.JsCredPostHits.Count >= 1)
            {
                // record a concrete self-id entry so the decisive floor (selfid + exfil) fires.
                if (r.MalwareSelfIdHits.Count == 0)
                    r.MalwareSelfIdHits.Add("js-credential-stealer pattern: " +
                                             string.Join(" | ", r.JsCredScraperHits.Take(2)));
                // MITRE — browser-form grabbing. T1056.003 (Web Portal Capture) fits perfectly.
                r.MitreTtps.Add("T1056.003");
                r.MitreTtps.Add("T1555.003");
            }

            if (r.JsStealerSelfIdHits.Count > 0 && scriptContext)
            {
                foreach (var hit in r.JsStealerSelfIdHits.Take(5))
                    r.MalwareSelfIdHits.Add("js-keyword: " + hit);
            }
        }

        private static int CountCredentialFieldTokens(string text)
        {
            int c = 0;
            foreach (var f in CredentialJsonFields)
            {
                if (text.IndexOf("\"" + f + "\"", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    text.IndexOf("'" + f + "'",   StringComparison.OrdinalIgnoreCase) >= 0)
                    c++;
            }
            return c;
        }

        // Score contribution for BB27. A full cred-stealer JS (scraper + POST +
        // self-id) contributes ~+50, pushing it into HIGH on its own.
        internal static int BrowserJsStealerBonus(AnalysisResult r)
        {
            int b = 0;
            b += Math.Min(25, r.JsCredScraperHits.Count   * 6);
            b += Math.Min(25, r.JsCredPostHits.Count      * 15);
            b += Math.Min(15, r.JsFormHookHits.Count      * 3);
            b += Math.Min(25, r.JsStealerSelfIdHits.Count * 8);
            // Combo bump — all three classes together is a very high confidence stealer.
            if (r.JsCredScraperHits.Count >= 1 && r.JsCredPostHits.Count >= 1 && r.JsFormHookHits.Count >= 1)
                b += 15;
            return Math.Min(60, b);
        }
    }
}
