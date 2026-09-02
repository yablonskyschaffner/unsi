// PR 8 — Section 10 (Sigma/YARA/CAPA detection engines): tests for the new
// SigmaFullEngine + CapaFullEngine + RulesUpdater pipelines.
//
// We focus on:
//   - Sigma parser/evaluator: backward-compat with the minimal format already
//     in rules/sigma/*.yml, plus the full surface: multiple selections, field
//     predicates with modifiers, condition grammar (and/or/not/(parens)/
//     "all of selection_*"), and special structured fields (Imports, Sha256,
//     ImpHash).
//   - CAPA parser/evaluator: legacy flat form, full YAML "rule:" form with
//     and/or/not/optional/N-or-more.
//   - RulesUpdater: directory source, _provenance.json round-trip,
//     deterministic content hash.
//   - Per-engine timeouts: very-slow regex predicate doesn't pin the engine.
//
// Tests live in their own xUnit collection so they don't race with the
// existing analyzer-touching suites that already serialise on
// EncryptedQuarantine.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests;

[Collection("EncryptedQuarantine")]
public class RulesEnginesTests
{
    private static AnalysisResult NewResult()
    {
        var r = new AnalysisResult("dummy.exe")
        {
            FileType = "PE",
            FormatFamily = "PE",
            Sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ImpHash = "deadbeefdeadbeefdeadbeefdeadbeef",
            Is64 = true,
        };
        return r;
    }

    private static string CreateTempDir(string prefix)
    {
        var p = Path.Combine(Path.GetTempPath(), prefix + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(p);
        return p;
    }

    // ------------------------------------------------------------------
    // Sigma — backwards compatibility with the legacy minimal format
    // ------------------------------------------------------------------

    [Fact]
    public void Sigma_LegacyMinimalRule_StillFires()
    {
        var dir = CreateTempDir("ast-sigma");
        try
        {
            File.WriteAllText(Path.Combine(dir, "telegram.yml"), """
title: Telegram exfil
detection:
  selection:
    - "api.telegram.org/bot"
    - "sendMessage"
    - "%s"
  condition: selection
""");
            var r = NewResult();
            SigmaFullEngine.Run(r, "stuff before api.telegram.org/bot more sendMessage and %s end", dir);
            Assert.Contains(r.SigmaFullHits, h => h.StartsWith("Telegram exfil"));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Sigma_MissingAnyKeywordPattern_NoHit()
    {
        var dir = CreateTempDir("ast-sigma");
        try
        {
            File.WriteAllText(Path.Combine(dir, "rule.yml"), """
title: Needs all three
detection:
  selection:
    - "alpha"
    - "beta"
    - "gamma"
  condition: selection
""");
            var r = NewResult();
            SigmaFullEngine.Run(r, "alpha beta", dir);
            Assert.Empty(r.SigmaFullHits);
        }
        finally { Directory.Delete(dir, true); }
    }

    // ------------------------------------------------------------------
    // Sigma — multiple selections, condition grammar
    // ------------------------------------------------------------------

    [Fact]
    public void Sigma_AndOfTwoSelections_BothRequired()
    {
        var dir = CreateTempDir("ast-sigma");
        try
        {
            File.WriteAllText(Path.Combine(dir, "twin.yml"), """
title: Twin selections
detection:
  selection_a:
    - "needle-a"
  selection_b:
    - "needle-b"
  condition: selection_a and selection_b
""");
            var r1 = NewResult();
            SigmaFullEngine.Run(r1, "needle-a only", dir);
            Assert.Empty(r1.SigmaFullHits);

            var r2 = NewResult();
            SigmaFullEngine.Run(r2, "needle-a and ALSO needle-b", dir);
            Assert.Single(r2.SigmaFullHits);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Sigma_OneOfWildcard_FiresOnAnyMatchingSelection()
    {
        var dir = CreateTempDir("ast-sigma");
        try
        {
            File.WriteAllText(Path.Combine(dir, "wild.yml"), """
title: 1 of selection_*
detection:
  selection_telegram:
    - "telegram.org/bot"
  selection_discord:
    - "discord.com/api/webhooks"
  selection_slack:
    - "hooks.slack.com"
  condition: 1 of selection_*
""");
            var r = NewResult();
            SigmaFullEngine.Run(r, "phone home via hooks.slack.com only", dir);
            Assert.Single(r.SigmaFullHits);
            Assert.Contains(r.SigmaFullHits, h => h.StartsWith("1 of selection_*"));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Sigma_NotCondition_ExcludesFalsePositive()
    {
        var dir = CreateTempDir("ast-sigma");
        try
        {
            // Use ASCII-only tokens to keep YAML-escape surface area zero
            // (the legacy minimal-Sigma parser does not unescape sequences
            // inside quoted scalars, and that's by design — patterns are
            // matched against the analysisText as-is).
            File.WriteAllText(Path.Combine(dir, "not.yml"), """
title: Suspicious unless system
detection:
  selection:
    - "CreateRemoteThread"
  filter:
    - "NT-AUTHORITY-SYSTEM"
  condition: selection and not filter
""");
            var withSystem = NewResult();
            SigmaFullEngine.Run(withSystem, "CreateRemoteThread by NT-AUTHORITY-SYSTEM", dir);
            Assert.Empty(withSystem.SigmaFullHits);

            var withUser = NewResult();
            SigmaFullEngine.Run(withUser, "CreateRemoteThread by some user", dir);
            Assert.Single(withUser.SigmaFullHits);
        }
        finally { Directory.Delete(dir, true); }
    }

    // ------------------------------------------------------------------
    // Sigma — field predicates with modifiers
    // ------------------------------------------------------------------

    [Fact]
    public void Sigma_FieldPredicate_EndswithMatchesText()
    {
        var dir = CreateTempDir("ast-sigma");
        try
        {
            File.WriteAllText(Path.Combine(dir, "endswith.yml"), """
title: Endswith powershell
detection:
  selection:
    Image|endswith: '\powershell.exe'
  condition: selection
""");
            var r = NewResult();
            SigmaFullEngine.Run(r, @"some other text C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", dir);
            Assert.Single(r.SigmaFullHits);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Sigma_FieldPredicate_AllModifier_RequiresEveryValue()
    {
        var dir = CreateTempDir("ast-sigma");
        try
        {
            File.WriteAllText(Path.Combine(dir, "all.yml"), """
title: All three
detection:
  selection:
    CommandLine|contains|all:
      - "-enc"
      - "IEX"
      - "FromBase64"
  condition: selection
""");
            var partial = NewResult();
            SigmaFullEngine.Run(partial, "powershell.exe -enc IEX without the third pattern", dir);
            Assert.Empty(partial.SigmaFullHits);

            var full = NewResult();
            SigmaFullEngine.Run(full, "powershell.exe -enc IEX([Convert]::FromBase64String('...'))", dir);
            Assert.Single(full.SigmaFullHits);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Sigma_FieldPredicate_ImportsField_MatchesAgainstImportedApis()
    {
        var dir = CreateTempDir("ast-sigma");
        try
        {
            File.WriteAllText(Path.Combine(dir, "imp.yml"), """
title: Injection imports
detection:
  selection:
    Imports|all:
      - "VirtualAllocEx"
      - "WriteProcessMemory"
      - "CreateRemoteThread"
  condition: selection
""");
            var r = NewResult();
            r.ImportedApis.Add("VirtualAllocEx");
            r.ImportedApis.Add("WriteProcessMemory");
            r.ImportedApis.Add("CreateRemoteThread");
            r.ImportedApis.Add("Sleep");
            SigmaFullEngine.Run(r, "", dir);
            Assert.Single(r.SigmaFullHits);

            var missing = NewResult();
            missing.ImportedApis.Add("VirtualAllocEx");
            missing.ImportedApis.Add("WriteProcessMemory");
            SigmaFullEngine.Run(missing, "", dir);
            Assert.Empty(missing.SigmaFullHits);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Sigma_FieldPredicate_Sha256_ExactEquals()
    {
        var dir = CreateTempDir("ast-sigma");
        try
        {
            File.WriteAllText(Path.Combine(dir, "sha.yml"), """
title: Known bad hash
detection:
  selection:
    Sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  condition: selection
""");
            var r = NewResult();
            SigmaFullEngine.Run(r, "irrelevant", dir);
            Assert.Single(r.SigmaFullHits);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Sigma_FieldPredicate_RegexModifier()
    {
        var dir = CreateTempDir("ast-sigma");
        try
        {
            // Single-quoted YAML scalar so backslashes survive verbatim
            // through our minimal Unquote() and reach .NET's regex engine.
            File.WriteAllText(Path.Combine(dir, "rx.yml"), @"title: Regex match
detection:
  selection:
    CommandLine|re: '-enc(?:odedcommand)?\s+[A-Za-z0-9+/]{40,}'
  condition: selection
");
            var r = NewResult();
            SigmaFullEngine.Run(r,
                "powershell -enc abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR0123456+/== xxx",
                dir);
            Assert.Single(r.SigmaFullHits);
        }
        finally { Directory.Delete(dir, true); }
    }

    // ------------------------------------------------------------------
    // Sigma — provenance & timings
    // ------------------------------------------------------------------

    [Fact]
    public void Sigma_RecordsProvenanceFromSidecarManifest()
    {
        var dir = CreateTempDir("ast-sigma");
        try
        {
            File.WriteAllText(Path.Combine(dir, "telegram.yml"), """
title: Telegram exfil
detection:
  selection:
    - "telegram.org/bot"
  condition: selection
""");
            File.WriteAllText(Path.Combine(dir, "_provenance.json"), """
{"engine":"sigma","source":"https://example.com/rules.zip","version":"2024.01.03","fetched_at_utc":"2024-01-03T12:00:00Z","sha256":"deadbeef","file_count":1,"signed":false,"signer_pubkey":""}
""");
            var r = NewResult();
            SigmaFullEngine.Run(r, "phoning home to api.telegram.org/bot12345/sendMessage", dir);
            Assert.Single(r.SigmaFullHits);
            Assert.Contains("telegram.yml", r.RulesProvenance.Keys);
            Assert.Equal("sigma", r.RulesProvenance["telegram.yml"].Engine);
            Assert.Equal("https://example.com/rules.zip", r.RulesProvenance["telegram.yml"].Source);
            Assert.Equal("2024.01.03", r.RulesProvenance["telegram.yml"].Version);
            Assert.True(r.RulesEngineTimingsMs.ContainsKey("sigma"));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Sigma_PerEngineTimeoutBudget_TerminatesEnumeration()
    {
        var dir = CreateTempDir("ast-sigma");
        try
        {
            for (int i = 0; i < 20; i++)
            {
                File.WriteAllText(Path.Combine(dir, $"r{i}.yml"), """
title: Match-all
detection:
  selection:
    - "x"
  condition: selection
""");
            }
            var prev = Environment.GetEnvironmentVariable("ANTISTEALER_RULES_TIMEOUT_MS");
            Environment.SetEnvironmentVariable("ANTISTEALER_RULES_TIMEOUT_MS", "0");
            try
            {
                var r = NewResult();
                SigmaFullEngine.Run(r, "x", dir);
                Assert.Contains("sigma:engine-budget", r.RulesEngineTimeouts);
            }
            finally
            {
                Environment.SetEnvironmentVariable("ANTISTEALER_RULES_TIMEOUT_MS", prev);
            }
        }
        finally { Directory.Delete(dir, true); }
    }

    // ------------------------------------------------------------------
    // CAPA — legacy flat form
    // ------------------------------------------------------------------

    [Fact]
    public void Capa_LegacyFlat_AllImportsRequired()
    {
        var dir = CreateTempDir("ast-capa");
        try
        {
            File.WriteAllText(Path.Combine(dir, "inject.capa"), """
capability: classic remote-thread injection
match: all
imports:
  - VirtualAllocEx
  - WriteProcessMemory
  - CreateRemoteThread
""");
            var partial = NewResult();
            partial.ImportedApis.Add("VirtualAllocEx");
            partial.ImportedApis.Add("WriteProcessMemory");
            CapaFullEngine.Run(partial, "", dir);
            Assert.Empty(partial.CapaHits);

            var full = NewResult();
            full.ImportedApis.Add("VirtualAllocEx");
            full.ImportedApis.Add("WriteProcessMemory");
            full.ImportedApis.Add("CreateRemoteThread");
            CapaFullEngine.Run(full, "", dir);
            Assert.Single(full.CapaHits);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Capa_LegacyFlat_MatchAny()
    {
        var dir = CreateTempDir("ast-capa");
        try
        {
            File.WriteAllText(Path.Combine(dir, "clip.capa"), """
capability: clipboard hijack
match: any
imports:
  - OpenClipboard
  - SetClipboardData
  - GetClipboardData
""");
            var r = NewResult();
            r.ImportedApis.Add("SetClipboardData");
            CapaFullEngine.Run(r, "", dir);
            Assert.Single(r.CapaHits);
        }
        finally { Directory.Delete(dir, true); }
    }

    // ------------------------------------------------------------------
    // CAPA — full YAML form
    // ------------------------------------------------------------------

    [Fact]
    public void Capa_FullYaml_AndOrNot()
    {
        var dir = CreateTempDir("ast-capa");
        try
        {
            File.WriteAllText(Path.Combine(dir, "v2.capa"), """
rule:
  meta:
    name: process injection (any technique)
    namespace: host-interaction/process/inject
    scopes:
      static: file
  features:
    - and:
        - or:
            - api: WriteProcessMemory
            - api: NtWriteVirtualMemory
        - api: CreateRemoteThread
        - not:
            - characteristic: signed
""");
            var hit = NewResult();
            hit.ImportedApis.Add("WriteProcessMemory");
            hit.ImportedApis.Add("CreateRemoteThread");
            // IsSigned defaults to false, so "not signed" is true.
            CapaFullEngine.Run(hit, "", dir);
            Assert.Single(hit.CapaHits);

            var signed = NewResult();
            signed.ImportedApis.Add("WriteProcessMemory");
            signed.ImportedApis.Add("CreateRemoteThread");
            signed.IsSigned = true;
            CapaFullEngine.Run(signed, "", dir);
            Assert.Empty(signed.CapaHits);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Capa_FullYaml_NorMore()
    {
        var dir = CreateTempDir("ast-capa");
        try
        {
            File.WriteAllText(Path.Combine(dir, "nm.capa"), """
rule:
  meta:
    name: at least two stealer strings
  features:
    - 2 or more:
        - string: "wallet"
        - string: "mnemonic"
        - string: "seed phrase"
        - string: "private key"
""");
            var one = NewResult();
            CapaFullEngine.Run(one, "only wallet here", dir);
            Assert.Empty(one.CapaHits);

            var two = NewResult();
            CapaFullEngine.Run(two, "wallet and mnemonic and seed phrase", dir);
            Assert.Single(two.CapaHits);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Capa_FullYaml_OptionalDoesNotBlockMatch()
    {
        var dir = CreateTempDir("ast-capa");
        try
        {
            File.WriteAllText(Path.Combine(dir, "opt.capa"), """
rule:
  meta:
    name: with optional metadata feature
  features:
    - and:
        - api: VirtualAlloc
        - optional:
            - string: "this string is never present in the sample"
""");
            var r = NewResult();
            r.ImportedApis.Add("VirtualAlloc");
            CapaFullEngine.Run(r, "", dir);
            Assert.Single(r.CapaHits);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Capa_Provenance_RecordedOnHit()
    {
        var dir = CreateTempDir("ast-capa");
        try
        {
            File.WriteAllText(Path.Combine(dir, "rule.capa"), """
capability: clipboard hijack
imports:
  - OpenClipboard
""");
            File.WriteAllText(Path.Combine(dir, "_provenance.json"), """
{"engine":"capa","source":"local","version":"vendor-2024.02","fetched_at_utc":"2024-02-01T00:00:00Z","sha256":"abc","file_count":1,"signed":false,"signer_pubkey":""}
""");
            var r = NewResult();
            r.ImportedApis.Add("OpenClipboard");
            CapaFullEngine.Run(r, "", dir);
            Assert.Single(r.CapaHits);
            Assert.True(r.RulesProvenance.ContainsKey("rule.capa"));
            Assert.Equal("vendor-2024.02", r.RulesProvenance["rule.capa"].Version);
        }
        finally { Directory.Delete(dir, true); }
    }

    // ------------------------------------------------------------------
    // RulesUpdater
    // ------------------------------------------------------------------

    [Fact]
    public void RulesUpdater_LocalDir_CopiesAndWritesProvenance()
    {
        var src = CreateTempDir("ast-src");
        var dst = CreateTempDir("ast-dst");
        try
        {
            // Source layout:  <src>/sigma/r.yml + <src>/capa/r.capa
            Directory.CreateDirectory(Path.Combine(src, "sigma"));
            Directory.CreateDirectory(Path.Combine(src, "capa"));
            File.WriteAllText(Path.Combine(src, "sigma", "r.yml"), "title: T\ndetection:\n  s:\n    - x\n  condition: s\n");
            File.WriteAllText(Path.Combine(src, "capa",  "r.capa"), "capability: cap\nimports:\n  - Foo\n");

            var res = RulesUpdater.Update(new RulesUpdateOptions
            {
                Engine = "sigma,capa",
                Source = src,
                Dest = dst,
                Version = "test-1",
            });

            Assert.Empty(res.Errors);
            Assert.True(File.Exists(Path.Combine(dst, "sigma", "r.yml")));
            Assert.True(File.Exists(Path.Combine(dst, "sigma", "_provenance.json")));
            Assert.True(File.Exists(Path.Combine(dst, "capa",  "r.capa")));
            Assert.True(File.Exists(Path.Combine(dst, "capa",  "_provenance.json")));
            Assert.NotNull(res.Manifest);
            Assert.Equal("test-1", res.Manifest!.Version);
        }
        finally
        {
            try { Directory.Delete(src, true); } catch { }
            try { Directory.Delete(dst, true); } catch { }
        }
    }

    [Fact]
    public void RulesUpdater_HashIsDeterministic()
    {
        var dir1 = CreateTempDir("ast-h1");
        var dir2 = CreateTempDir("ast-h2");
        try
        {
            File.WriteAllText(Path.Combine(dir1, "a.yml"), "x");
            File.WriteAllText(Path.Combine(dir1, "b.yml"), "y");
            File.WriteAllText(Path.Combine(dir2, "a.yml"), "x");
            File.WriteAllText(Path.Combine(dir2, "b.yml"), "y");
            Assert.Equal(RulesUpdater.HashDirectory(dir1), RulesUpdater.HashDirectory(dir2));

            File.WriteAllText(Path.Combine(dir2, "b.yml"), "y-modified");
            Assert.NotEqual(RulesUpdater.HashDirectory(dir1), RulesUpdater.HashDirectory(dir2));
        }
        finally
        {
            try { Directory.Delete(dir1, true); } catch { }
            try { Directory.Delete(dir2, true); } catch { }
        }
    }

    [Fact]
    public void RulesUpdater_NoSource_OnlyEnsuresDirectories()
    {
        var dst = CreateTempDir("ast-empty");
        try
        {
            var res = RulesUpdater.Update(new RulesUpdateOptions { Engine = "sigma", Dest = dst });
            Assert.Empty(res.Errors);
            Assert.True(Directory.Exists(Path.Combine(dst, "sigma")));
        }
        finally { try { Directory.Delete(dst, true); } catch { } }
    }

    [Fact]
    public void RulesUpdater_RejectsUnrecognisedSource()
    {
        var dst = CreateTempDir("ast-bad");
        try
        {
            var res = RulesUpdater.Update(new RulesUpdateOptions
            {
                Engine = "sigma",
                Source = "ftp://example.invalid/rules.tar",
                Dest = dst,
            });
            Assert.NotEmpty(res.Errors);
        }
        finally { try { Directory.Delete(dst, true); } catch { } }
    }

    // ------------------------------------------------------------------
    // YaraX engine selection
    // ------------------------------------------------------------------

    [Fact]
    public void YaraX_BuildArgs_PrefersYaraXSyntax()
    {
        var x = YaraXEngine.BuildArgs(isYaraX: true,  "/r/foo.yar", "/t/sample.bin");
        var y = YaraXEngine.BuildArgs(isYaraX: false, "/r/foo.yar", "/t/sample.bin");
        Assert.Equal(new[] { "scan", "-q", "/r/foo.yar", "/t/sample.bin" }, x.ToArray());
        Assert.Equal(new[] { "-w", "-N", "/r/foo.yar", "/t/sample.bin" }, y.ToArray());
    }

    // ------------------------------------------------------------------
    // Sigma tokeniser unit test (small but valuable: catches the wildcard
    // handling regression that broke "1 of selection_*" in the old impl).
    // ------------------------------------------------------------------

    [Fact]
    public void Sigma_Tokenise_HandlesParenthesesAndOperators()
    {
        var t = SigmaFullEngine.TokeniseCondition("(selection_a and selection_b) or not selection_c");
        Assert.Equal(new[] { "(", "selection_a", "and", "selection_b", ")", "or", "not", "selection_c" }, t.ToArray());
    }

    [Fact]
    public void Sigma_Tokenise_KeepsCountExprIntact()
    {
        var t = SigmaFullEngine.TokeniseCondition("count(selection_*) >= 2");
        Assert.Equal(new[] { "count(selection_*)", ">=", "2" }, t.ToArray());
    }

    // ─────────────────────────────────────────────────────────────
    //  C19 — Sigma fact-based fields (pe.sections / strings.decoded
    //         / urls.host / dynamic.net_post / format.family).
    // ─────────────────────────────────────────────────────────────

    [Fact]
    public void Sigma_FactBased_PeSectionsField_Matches()
    {
        var dir = CreateTempDir("ast-sigma-c19-pe");
        try
        {
            File.WriteAllText(Path.Combine(dir, "upx.yml"), """
title: UPX section layout
detection:
  selection:
    pe.sections: ".upx0"
  condition: selection
""");
            var r = NewResult();
            r.SectionNames.Add(".text");
            r.SectionNames.Add(".UPX0");
            r.SectionNames.Add(".UPX1");
            SigmaFullEngine.Run(r, "", dir);
            Assert.Contains(r.SigmaFullHits, h => h.StartsWith("UPX section layout"));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Sigma_FactBased_UrlsHostField_EndsWithMatches()
    {
        var dir = CreateTempDir("ast-sigma-c19-host");
        try
        {
            File.WriteAllText(Path.Combine(dir, "discord.yml"), """
title: Discord exfil host
detection:
  selection:
    urls.host|endswith: "discord.com"
  condition: selection
""");
            var r = NewResult();
            r.UrlsFound.Add("https://canary.discord.com/api/v9/channels/123");
            SigmaFullEngine.Run(r, "", dir);
            Assert.Contains(r.SigmaFullHits, h => h.StartsWith("Discord exfil host"));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Sigma_FactBased_StringsDecodedField_Matches()
    {
        var dir = CreateTempDir("ast-sigma-c19-decoded");
        try
        {
            File.WriteAllText(Path.Combine(dir, "loginbash.yml"), """
title: Decoded Login Data string
detection:
  selection:
    strings.decoded: "login data"
  condition: selection
""");
            var r = NewResult();
            r.DeobfuscatedHits.Add("Chrome\\User Data\\Default\\Login Data");
            SigmaFullEngine.Run(r, "", dir);
            Assert.Contains(r.SigmaFullHits, h => h.StartsWith("Decoded Login Data string"));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Sigma_FactBased_UnknownFactField_FallsBackToText()
    {
        // An unrecognised field falls through to the AnalysisText match path
        // and doesn't crash the engine.
        var dir = CreateTempDir("ast-sigma-c19-unknown");
        try
        {
            File.WriteAllText(Path.Combine(dir, "u.yml"), """
title: Unknown field falls through
detection:
  selection:
    not_a_real_field: "needle"
  condition: selection
""");
            var r = NewResult();
            SigmaFullEngine.Run(r, "this is the needle in haystack", dir);
            Assert.Contains(r.SigmaFullHits, h => h.StartsWith("Unknown field falls through"));
        }
        finally { Directory.Delete(dir, true); }
    }
}
