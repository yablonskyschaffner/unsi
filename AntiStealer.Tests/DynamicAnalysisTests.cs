using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests
{
    public class DynamicAnalysisTests
    {
        // 4.1 -----------------------------------------------------------

        [Fact]
        public void Wsb_Xml_HasNetworkingDisabled_ByDefault()
        {
            var cfg = new WsbSandboxRunner.WsbConfig(MappedHostPath: @"C:\samples");
            string xml = WsbSandboxRunner.BuildXml(cfg);
            Assert.Contains("<Networking>Disable</Networking>",   xml);
            Assert.Contains("<AudioInput>Disable</AudioInput>",   xml);
            Assert.Contains("<VideoInput>Disable</VideoInput>",   xml);
            Assert.Contains("<HostFolder>C:\\samples</HostFolder>", xml);
            Assert.Contains("<ReadOnly>true</ReadOnly>",          xml);
            Assert.DoesNotContain("<LogonCommand>", xml);
        }

        [Fact]
        public void Wsb_Xml_EscapesAngleBrackets()
        {
            var cfg = new WsbSandboxRunner.WsbConfig(MappedHostPath: "C:\\bad<dir>");
            string xml = WsbSandboxRunner.BuildXml(cfg);
            Assert.Contains("C:\\bad&lt;dir&gt;", xml);
        }

        [Fact]
        public void Wsb_Xml_IncludesLogonCommand_WhenProvided()
        {
            var cfg = new WsbSandboxRunner.WsbConfig(
                MappedHostPath: @"C:\samples",
                LogonCommand: "cmd /c C:\\sample\\runme.exe");
            string xml = WsbSandboxRunner.BuildXml(cfg);
            Assert.Contains("<LogonCommand>",                            xml);
            Assert.Contains("<Command>cmd /c C:\\sample\\runme.exe</Command>", xml);
        }

        [Fact]
        public void Wsb_Transcript_Parse_FiltersKnownPrefixes()
        {
            string transcript = string.Join("\n", new[]
            {
                "PROCESS: cmd.exe spawned powershell.exe",
                "NET: tcp 127.0.0.1:445 -> 1.2.3.4:443",
                "REG: HKLM\\Software\\Malware",
                "FILE: C:\\Users\\u\\AppData\\Roaming\\dropper.exe",
                "noise that should be ignored",
            });
            var hits = WsbSandboxRunner.ParseTranscript(transcript);
            Assert.Equal(4, hits.Count);
            Assert.Contains("wsb:PROCESS: cmd.exe spawned powershell.exe",     hits);
            Assert.Contains("wsb:NET: tcp 127.0.0.1:445 -> 1.2.3.4:443",       hits);
            Assert.Contains("wsb:REG: HKLM\\Software\\Malware",                hits);
            Assert.Contains("wsb:FILE: C:\\Users\\u\\AppData\\Roaming\\dropper.exe", hits);
        }

        // 4.2 -----------------------------------------------------------

        [Fact]
        public void Etw_Parse_KnownProvidersOnly()
        {
            string csv = string.Join("\n", new[]
            {
                "Provider,Task,Opcode,Process,Detail",
                "Microsoft-Windows-DNS-Client,QueryStarted,1,evil.exe,evil.com",
                "Microsoft-Windows-Kernel-Process,ProcessStart,1,evil.exe,",
                "Microsoft-Windows-NotARealOne,Foo,1,x,",
                "Microsoft-Windows-Services,ServiceInstall,1,svc.exe,",
            });
            var ev = EtwTraceReader.Parse(csv);
            Assert.Contains("etw:dns:QueryStarted",  ev);
            Assert.Contains("etw:proc:ProcessStart", ev);
            Assert.Contains("etw:svc:ServiceInstall",ev);
            Assert.DoesNotContain("etw:NotARealOne", ev);
        }

        [Fact]
        public void Etw_Parse_DeduplicatesAcrossLines()
        {
            string csv = string.Join("\n", new[]
            {
                "Provider,Task,Opcode,Process,Detail",
                "Microsoft-Windows-DNS-Client,QueryStarted,1,a.exe,a.com",
                "Microsoft-Windows-DNS-Client,QueryStarted,1,b.exe,b.com",
            });
            var ev = EtwTraceReader.Parse(csv);
            Assert.Single(ev);
            Assert.Contains("etw:dns:QueryStarted", ev);
        }

        // 4.3 -----------------------------------------------------------

        [Fact]
        public void Emulator_DecodesCommonOpcodes()
        {
            // PUSH RBP; MOV; SYSCALL; RET
            byte[] code = { 0x55, 0x90, 0x0F, 0x05, 0xC3 };
            var trace = UnicornEmulator.Trace(code);
            Assert.Contains("0x0000: push r5", trace);   // 0x55 = push rbp(5)
            Assert.Contains("0x0001: nop",     trace);
            Assert.Contains("0x0002: syscall", trace);
            Assert.Contains("0x0004: ret",     trace);
            // RET terminates the loop — no further entries.
            Assert.Equal(4, trace.Count);
        }

        [Fact]
        public void Emulator_StopsAt_MaxSteps()
        {
            byte[] code = new byte[200]; // 200 nops — only 8 steps allowed.
            var trace = UnicornEmulator.Trace(code, maxSteps: 8);
            Assert.Equal(8, trace.Count);
        }

        // 4.4 -----------------------------------------------------------

        private sealed class FakeHandler : HttpMessageHandler
        {
            public Func<HttpRequestMessage, HttpResponseMessage>? Responder;
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage req, CancellationToken ct)
                => Task.FromResult(Responder!(req));
        }

        [Fact]
        public async Task CapeClient_Submit_ParsesTaskId()
        {
            var fake = new FakeHandler
            {
                Responder = req =>
                {
                    Assert.Contains("tasks/create/file", req.RequestUri!.ToString());
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("{\"task_id\":42}"),
                    };
                }
            };
            string tmp = Path.GetTempFileName();
            try
            {
                File.WriteAllText(tmp, "hello");
                var client = new CapeClient(new CapeOptions { BaseUrl = "http://x" }, fake);
                int id = await client.SubmitAsync(tmp);
                Assert.Equal(42, id);
            }
            finally { File.Delete(tmp); }
        }

        [Fact]
        public async Task CapeClient_Poll_ReturnsReported()
        {
            var fake = new FakeHandler
            {
                Responder = req => new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"task\":{\"status\":\"reported\"}}"),
                }
            };
            var client = new CapeClient(new CapeOptions { BaseUrl = "http://x", PollInterval = TimeSpan.Zero, MaxWait = TimeSpan.FromSeconds(1) }, fake);
            var status = await client.PollAsync(7);
            Assert.Equal("reported", status);
        }

        [Fact]
        public void CapeClient_MergeReport_ProducesPrefixedEvents()
        {
            var rep = new CapeReport
            {
                Processes = new() { "evil.exe", "child.exe" },
                Dns       = new() { "evil.com" },
                Dropped   = new() { "C:\\u\\dropper.bin" },
            };
            var ev = CapeClient.MergeReport(rep);
            Assert.Contains("cape:proc:evil.exe",            ev);
            Assert.Contains("cape:proc:child.exe",           ev);
            Assert.Contains("cape:dns:evil.com",             ev);
            Assert.Contains("cape:drop:C:\\u\\dropper.bin",  ev);
        }

        // 4.5 -----------------------------------------------------------

        [Fact]
        public void MiniYaraX_Parse_ExtractsStringsAndCondition()
        {
            var rule = MiniYaraXParser.Parse(
                "rule SampleStealer { strings: $s1 = \"AppData\\\\Local\" $s2 = /\\$pwd/ condition: any of them }");
            Assert.Equal("SampleStealer", rule.Name);
            Assert.Equal(2, rule.Strings.Count);
            Assert.Equal("any", rule.Condition);
            Assert.False(rule.Strings[0].IsRegex);
            Assert.True(rule.Strings[1].IsRegex);
        }

        [Fact]
        public void MiniYaraX_RunOn_FiresOn_AnyOfThem()
        {
            var rule = MiniYaraXParser.Parse(
                "rule R { strings: $s1 = \"redline\" $s2 = \"lumma\" condition: any of them }");
            var r = new AnalysisResult("x");
            r.StringHits.Add("contains redline marker");
            var hits = MiniYaraXEngine.RunOn(new[] { rule }, r);
            Assert.Contains("yarax:R", hits);
        }

        [Fact]
        public void MiniYaraX_RunOn_NoFire_AllOfThem_WhenPartial()
        {
            var rule = MiniYaraXParser.Parse(
                "rule R { strings: $s1 = \"a\" $s2 = \"b\" $s3 = \"c\" condition: all of them }");
            var r = new AnalysisResult("x");
            r.StringHits.AddRange(new[] { "contains a only" });
            var hits = MiniYaraXEngine.RunOn(new[] { rule }, r);
            Assert.Empty(hits);
        }

        [Fact]
        public void MiniYaraX_RunOn_Fires_NofThem_WhenThresholdMet()
        {
            var rule = MiniYaraXParser.Parse(
                "rule R { strings: $s1 = \"a\" $s2 = \"b\" $s3 = \"c\" condition: 2 of them }");
            var r = new AnalysisResult("x");
            r.StringHits.AddRange(new[] { "a and b appear" });
            var hits = MiniYaraXEngine.RunOn(new[] { rule }, r);
            Assert.Contains("yarax:R", hits);
        }

        [Fact]
        public void MiniYaraX_Pipeline_Idempotent()
        {
            var rule = MiniYaraXParser.Parse(
                "rule R { strings: $s1 = \"foo\" condition: any of them }");
            var r = new AnalysisResult("x");
            r.StringHits.Add("foo");
            DynamicAnalysisPipeline.RunOn(r, new[] { rule });
            int after = r.MiniYaraXHits.Count;
            DynamicAnalysisPipeline.RunOn(r, new[] { rule });
            Assert.Equal(after, r.MiniYaraXHits.Count);
        }

        [Fact]
        public void MiniYaraX_EmptyStringsBlock_NeverFires()
        {
            // Regression: previously a rule whose `strings:` block was empty
            // (or where the parser failed to extract any strings) would
            // fire on every sample with condition `all of them` because
            // `matched == rule.Strings.Count` evaluated `0 == 0 = true`.
            // After the fix an empty rule must never fire.
            var rule = new MiniYaraXRule { Name = "Empty", Condition = "all" };
            var r = new AnalysisResult("x");
            r.StringHits.Add("anything");
            var hits = MiniYaraXEngine.RunOn(new[] { rule }, r);
            Assert.DoesNotContain("yarax:Empty", hits);

            // Same for "any" and "N of them".
            rule.Condition = "any";
            Assert.DoesNotContain("yarax:Empty", MiniYaraXEngine.RunOn(new[] { rule }, r));
            rule.Condition = "0";
            Assert.DoesNotContain("yarax:Empty", MiniYaraXEngine.RunOn(new[] { rule }, r));
        }

        // D10 — canary dynamic-analysis profile -------------------------

        private static string TmpProfileDir()
        {
            var d = Path.Combine(Path.GetTempPath(), "ast-canary-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(d);
            return d;
        }

        [Fact]
        public void D10_CanarySeed_CreatesExpectedBrowserAndCredentialTargets()
        {
            var root = TmpProfileDir();
            try
            {
                var prof = DynamicCanaryProfile.Seed(root);
                Assert.NotEmpty(prof.Files);
                // Browser DBs across Chrome/Edge/Brave/Yandex
                Assert.Contains(prof.Files.Keys, p => p.EndsWith(Path.Combine("Chrome", "User Data", "Default", "Login Data")));
                Assert.Contains(prof.Files.Keys, p => p.EndsWith(Path.Combine("Edge",   "User Data", "Default", "Cookies")));
                // Discord LevelDB
                Assert.Contains(prof.Files.Keys, p => p.Replace('\\','/').Contains("discord/Local Storage/leveldb/"));
                // Telegram tdata
                Assert.Contains(prof.Files.Keys, p => p.EndsWith(Path.Combine("Telegram Desktop", "tdata", "key_datas")));
                // Wallet artifacts
                Assert.Contains(prof.Files.Keys, p => p.EndsWith("wallet.dat"));
                Assert.Contains(prof.Files.Keys, p => p.EndsWith(Path.Combine("Exodus", "exodus.wallet", "passphrase.json")));
                // Cloud/dev secrets
                Assert.Contains(prof.Files.Keys, p => p.EndsWith(".env"));
                Assert.Contains(prof.Files.Keys, p => p.EndsWith(Path.Combine(".aws", "credentials")));
                Assert.Contains(prof.Files.Keys, p => p.EndsWith(Path.Combine(".ssh", "id_rsa")));
                // Each canary file contains the token marker
                foreach (var cf in prof.Files.Values)
                {
                    var content = File.ReadAllText(cf.Path);
                    Assert.Contains(prof.CanaryToken, content);
                }
            }
            finally { try { Directory.Delete(root, true); } catch {} }
        }

        [Fact]
        public void D10_CanaryAudit_DetectsDeletionAndModification()
        {
            var root = TmpProfileDir();
            try
            {
                var prof = DynamicCanaryProfile.Seed(root);
                var anyPath = prof.Files.Keys.First(p => p.EndsWith("Login Data"));
                File.Delete(anyPath);
                var otherPath = prof.Files.Keys.First(p => p.EndsWith("Cookies"));
                System.Threading.Thread.Sleep(1200);
                File.WriteAllText(otherPath, "tampered");

                var events = prof.Audit();
                Assert.Contains(events, e => e.StartsWith("wsb:FILE:deleted:"));
                Assert.Contains(events, e => e.StartsWith("wsb:FILE:modified:") || e.StartsWith("wsb:FILE:write:"));
            }
            finally { try { Directory.Delete(root, true); } catch {} }
        }

        [Fact]
        public void D10_CanaryScanForExfilTokens_FindsTokenInExternalFile()
        {
            var root  = TmpProfileDir();
            var exDir = TmpProfileDir();
            try
            {
                var prof = DynamicCanaryProfile.Seed(root);
                // Simulate sample staging stolen creds in %TEMP%/stolen.txt
                var stolen = Path.Combine(exDir, "stolen.txt");
                File.WriteAllText(stolen, "begin\n" + prof.CanaryToken + "\nend\n");

                var events = prof.ScanForExfilTokens(exDir);
                Assert.Contains(events, e => e.StartsWith("wsb:NET:exfil_stage:") && e.Contains("stolen.txt"));
            }
            finally
            {
                try { Directory.Delete(root,  true); } catch {}
                try { Directory.Delete(exDir, true); } catch {}
            }
        }

        [Fact]
        public void D10_CanaryScanForExfilTokens_HandlesMissingDirectory()
        {
            var root = TmpProfileDir();
            try
            {
                var prof = DynamicCanaryProfile.Seed(root);
                var events = prof.ScanForExfilTokens(Path.Combine(root, "does", "not", "exist"));
                Assert.Empty(events);
            }
            finally { try { Directory.Delete(root, true); } catch {} }
        }

        [Fact]
        public void D10_CanaryCleanup_RemovesProfile()
        {
            var root = TmpProfileDir();
            var prof = DynamicCanaryProfile.Seed(root);
            Assert.True(Directory.Exists(root));
            prof.Cleanup();
            Assert.False(Directory.Exists(root));
        }
    }
}
