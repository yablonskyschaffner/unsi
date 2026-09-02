using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests
{
    [Collection("EncryptedQuarantine")]
    public class IntelProvidersTests
    {
        // ------------------------------------------------------------------
        // helpers
        // ------------------------------------------------------------------

        private static string TmpDir()
        {
            var d = Path.Combine(Path.GetTempPath(), "ast-intel-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(d);
            return d;
        }

        private sealed class StubHandler : HttpMessageHandler
        {
            public Func<HttpRequestMessage, HttpResponseMessage> Responder = _ =>
                new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}", Encoding.UTF8, "application/json") };

            public int Calls { get; private set; }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                Calls++;
                return Task.FromResult(Responder(request));
            }
        }

        private sealed class FakeProvider : IIntelProvider
        {
            public string Name { get; }
            public IntelCapability Capabilities { get; }
            public Func<IntelIndicator, IntelLookupResult>? OnLookup;
            public Func<bool>? OnPreflight;
            public int LookupCount { get; private set; }
            public int PreflightCount { get; private set; }

            public FakeProvider(string name = "FAKE",
                                IntelCapability caps = IntelCapability.FileSha256 | IntelCapability.Url | IntelCapability.Ipv4 | IntelCapability.Domain)
            {
                Name = name;
                Capabilities = caps;
            }

            public bool Supports(IndicatorKind kind) => (Capabilities & ToCap(kind)) != 0;

            public Task<bool> PreflightAsync(CancellationToken ct)
            {
                PreflightCount++;
                return Task.FromResult(OnPreflight?.Invoke() ?? true);
            }

            public Task<IntelLookupResult> LookupAsync(IntelIndicator ind, CancellationToken ct)
            {
                LookupCount++;
                var r = OnLookup?.Invoke(ind) ?? new IntelLookupResult
                {
                    Provider     = Name,
                    Kind         = ind.Kind,
                    Indicator    = ind.Value,
                    FetchedAtUtc = DateTime.UtcNow,
                    Ttl          = TimeSpan.FromMinutes(5),
                    Verdict      = IntelVerdict.Unknown,
                };
                return Task.FromResult(r);
            }

            private static IntelCapability ToCap(IndicatorKind k) => k switch
            {
                IndicatorKind.FileSha256 => IntelCapability.FileSha256,
                IndicatorKind.Url        => IntelCapability.Url,
                IndicatorKind.Ipv4       => IntelCapability.Ipv4,
                IndicatorKind.Domain     => IntelCapability.Domain,
                _                        => IntelCapability.None,
            };
        }

        // ------------------------------------------------------------------
        // IntelCache
        // ------------------------------------------------------------------

        [Fact]
        public void IntelCache_HitMissExpiration()
        {
            var cache = new IntelCache(defaultTtl: TimeSpan.FromMilliseconds(50));
            var ind = new IntelIndicator(IndicatorKind.FileSha256, "abc");
            Assert.False(cache.TryGet("P", ind, out _));

            cache.Put("P", ind, new IntelLookupResult
            {
                Provider = "P", Kind = IndicatorKind.FileSha256, Indicator = "abc",
                FetchedAtUtc = DateTime.UtcNow, Ttl = TimeSpan.FromHours(1),
                Verdict = IntelVerdict.Malicious,
            });
            Assert.True(cache.TryGet("P", ind, out var hit));
            Assert.NotNull(hit);
            Assert.Equal(IntelVerdict.Malicious, hit!.Verdict);

            // forge expiration
            cache.Put("P", ind, new IntelLookupResult
            {
                Provider = "P", Kind = IndicatorKind.FileSha256, Indicator = "abc",
                FetchedAtUtc = DateTime.UtcNow - TimeSpan.FromHours(2),
                Ttl = TimeSpan.FromHours(1),
                Verdict = IntelVerdict.Malicious,
            });
            Assert.False(cache.TryGet("P", ind, out _));
        }

        [Fact]
        public void IntelCache_PersistAndReload()
        {
            var dir = TmpDir();
            try
            {
                var path = Path.Combine(dir, "cache.json");
                var c1 = new IntelCache(path);
                c1.Put("P", new IntelIndicator(IndicatorKind.Url, "https://evil"),
                       new IntelLookupResult
                       {
                           Provider = "P", Kind = IndicatorKind.Url, Indicator = "https://evil",
                           FetchedAtUtc = DateTime.UtcNow, Ttl = TimeSpan.FromHours(1),
                           Verdict = IntelVerdict.Malicious, Summary = "evil",
                       });
                c1.Persist();

                var c2 = new IntelCache(path);
                Assert.True(c2.TryGet("P", new IntelIndicator(IndicatorKind.Url, "https://evil"), out var hit));
                Assert.NotNull(hit);
                Assert.Equal("evil", hit!.Summary);
            }
            finally { Directory.Delete(dir, true); }
        }

        // ------------------------------------------------------------------
        // IntelRetryPolicy
        // ------------------------------------------------------------------

        [Fact]
        public async Task RetryPolicy_RetriesUntilSuccessOrMaxAttempts()
        {
            int attempts = 0;
            var pol = new IntelRetryPolicy
            {
                MaxAttempts = 3,
                BaseDelay = TimeSpan.FromMilliseconds(1),
                DelayOverride = _ => TimeSpan.FromMilliseconds(1),
            };
            var r = await pol.ExecuteAsync(
                (a, _) => { attempts = a; return Task.FromResult(a == 3 ? "ok" : "err"); },
                v => v == "err",
                CancellationToken.None);
            Assert.Equal("ok", r);
            Assert.Equal(3, attempts);
        }

        [Fact]
        public async Task RetryPolicy_StopsAfterMaxAttempts()
        {
            int attempts = 0;
            var pol = new IntelRetryPolicy
            {
                MaxAttempts = 2,
                DelayOverride = _ => TimeSpan.FromMilliseconds(1),
            };
            var r = await pol.ExecuteAsync(
                (a, _) => { attempts = a; return Task.FromResult("err"); },
                v => v == "err",
                CancellationToken.None);
            Assert.Equal("err", r);
            Assert.Equal(2, attempts);
        }

        [Fact]
        public void RetryPolicy_DelayBackoffMonotone()
        {
            var pol = new IntelRetryPolicy { BaseDelay = TimeSpan.FromMilliseconds(100), MaxDelay = TimeSpan.FromSeconds(5) };
            var d1 = pol.DelayFor(1);
            var d3 = pol.DelayFor(3);
            // d3 should generally be ≥ d1 (with jitter we still expect 2^2 > 1 base ratio).
            Assert.True(d3 >= d1 - TimeSpan.FromMilliseconds(80));
        }

        // ------------------------------------------------------------------
        // LocalThreatIntelProvider
        // ------------------------------------------------------------------

        [Fact]
        public async Task LocalThreatIntel_LoadsAllKinds_AndMatches()
        {
            var dir = TmpDir();
            try
            {
                var f = Path.Combine(dir, "ti.txt");
                File.WriteAllText(f,
                    "# comment\n" +
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" +
                    "http://evil.example/a\n" +
                    "1.2.3.4\n" +
                    "evil.example\n");
                var prov = new LocalThreatIntelProvider(f);
                Assert.Equal(1, prov.LoadedSha256);
                Assert.Equal(1, prov.LoadedUrls);
                Assert.Equal(1, prov.LoadedIps);
                Assert.Equal(1, prov.LoadedDomains);

                var hit = await prov.LookupAsync(new IntelIndicator(IndicatorKind.Ipv4, "1.2.3.4"), default);
                Assert.Equal(IntelVerdict.Malicious, hit.Verdict);

                var miss = await prov.LookupAsync(new IntelIndicator(IndicatorKind.Ipv4, "9.9.9.9"), default);
                Assert.Equal(IntelVerdict.Unknown, miss.Verdict);
            }
            finally { Directory.Delete(dir, true); }
        }

        [Fact]
        public async Task LocalThreatIntel_Preflight_FailsWhenFileMissing()
        {
            var prov = new LocalThreatIntelProvider("/no/such/file.txt");
            Assert.False(await prov.PreflightAsync(default));
        }

        // ------------------------------------------------------------------
        // ThreatFoxProvider / OtxProvider — wire format
        // ------------------------------------------------------------------

        [Fact]
        public async Task ThreatFox_MatchesQueryStatusOk()
        {
            var h = new StubHandler
            {
                Responder = _ => new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        "{\"query_status\":\"ok\",\"data\":[{\"malware\":\"Emotet\",\"threat_type\":\"botnet_cc\"}]}",
                        Encoding.UTF8, "application/json"),
                },
            };
            var p = new ThreatFoxProvider(h);
            var r = await p.LookupAsync(new IntelIndicator(IndicatorKind.FileSha256, "ab"), default);
            Assert.Equal(IntelVerdict.Malicious, r.Verdict);
            Assert.Contains("Emotet", r.Summary);
        }

        [Fact]
        public async Task ThreatFox_NoResultLeavesVerdictUnknown()
        {
            var h = new StubHandler
            {
                Responder = _ => new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"query_status\":\"no_result\"}", Encoding.UTF8, "application/json"),
                },
            };
            var p = new ThreatFoxProvider(h);
            var r = await p.LookupAsync(new IntelIndicator(IndicatorKind.Url, "http://e"), default);
            Assert.Equal(IntelVerdict.Unknown, r.Verdict);
        }

        [Fact]
        public async Task Otx_PreflightFailsWithoutApiKey()
        {
            var p = new OtxProvider("");
            Assert.False(await p.PreflightAsync(default));
        }

        [Fact]
        public async Task Otx_PulseCount_DrivesVerdict()
        {
            var h = new StubHandler
            {
                Responder = _ => new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        "{\"pulse_info\":{\"pulse_count\":5,\"count\":5}}",
                        Encoding.UTF8, "application/json"),
                },
            };
            var p = new OtxProvider("KEY", h);
            var r = await p.LookupAsync(new IntelIndicator(IndicatorKind.Ipv4, "1.2.3.4"), default);
            Assert.Equal(IntelVerdict.Malicious, r.Verdict);
            Assert.Contains("pulses=5", r.Summary);
        }

        // ------------------------------------------------------------------
        // Orchestrator
        // ------------------------------------------------------------------

        [Fact]
        public async Task Orchestrator_DropsProvidersFailingPreflight()
        {
            var alive = new FakeProvider("ALIVE");
            var dead  = new FakeProvider("DEAD") { OnPreflight = () => false };
            var orch  = new IntelOrchestrator(new IIntelProvider[] { alive, dead });

            var look = await orch.LookupAsync(new[] { new IntelIndicator(IndicatorKind.FileSha256, "h") }, default);
            Assert.Single(look);
            Assert.Equal("ALIVE", look[0].Provider);
            Assert.Equal(0, dead.LookupCount);
        }

        [Fact]
        public async Task Orchestrator_HonorsCache_OnSecondCall()
        {
            var p = new FakeProvider("P")
            {
                OnLookup = ind => new IntelLookupResult
                {
                    Provider = "P", Kind = ind.Kind, Indicator = ind.Value,
                    FetchedAtUtc = DateTime.UtcNow, Ttl = TimeSpan.FromMinutes(5),
                    Verdict = IntelVerdict.Malicious,
                },
            };
            var orch = new IntelOrchestrator(new[] { p });
            var ind = new IntelIndicator(IndicatorKind.FileSha256, "abc");
            await orch.LookupAsync(new[] { ind }, default);
            await orch.LookupAsync(new[] { ind }, default);
            Assert.Equal(1, p.LookupCount);
        }

        [Fact]
        public async Task Orchestrator_DeduplicatesIndicators()
        {
            var p = new FakeProvider("P");
            var orch = new IntelOrchestrator(new[] { p });
            await orch.LookupAsync(new[]
            {
                new IntelIndicator(IndicatorKind.Ipv4, "1.2.3.4"),
                new IntelIndicator(IndicatorKind.Ipv4, "1.2.3.4"),
                new IntelIndicator(IndicatorKind.Ipv4, "1.2.3.4"),
            }, default);
            Assert.Equal(1, p.LookupCount);
        }

        [Fact]
        public async Task Orchestrator_SkipsUnsupportedKind()
        {
            var p = new FakeProvider("P", IntelCapability.FileSha256);
            var orch = new IntelOrchestrator(new[] { p });
            await orch.LookupAsync(new[] { new IntelIndicator(IndicatorKind.Url, "http://x") }, default);
            Assert.Equal(0, p.LookupCount);
        }

        // ------------------------------------------------------------------
        // PCAP reader
        // ------------------------------------------------------------------

        [Fact]
        public void PcapReader_RejectsNonLibpcap()
        {
            var ind = PcapReader.Read(new MemoryStream(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24 }));
            Assert.Empty(ind.Ipv4);
            Assert.Empty(ind.Domains);
        }

        [Fact]
        public void PcapReader_ExtractsIpv4Destination()
        {
            // Build a one-packet libpcap file: Ethernet + IPv4 (dst=8.8.8.8) + UDP (53) + DNS A "example.com"
            var pkt = BuildEthernetIpv4UdpDnsAQuery("8.8.8.8", "example.com");
            byte[] file = BuildPcapFile(pkt);

            var ind = PcapReader.Read(new MemoryStream(file));
            Assert.Contains("8.8.8.8", ind.Ipv4);
            Assert.Contains("example.com", ind.Domains);
            Assert.Equal(1, ind.PacketCount);
        }

        [Fact]
        public void PcapReader_AcceptsSwappedMagic()
        {
            var pkt = BuildEthernetIpv4UdpDnsAQuery("1.2.3.4", "evil.tld");
            byte[] file = BuildPcapFile(pkt, swap: true);

            var ind = PcapReader.Read(new MemoryStream(file));
            Assert.Contains("1.2.3.4", ind.Ipv4);
            Assert.Contains("evil.tld", ind.Domains);
        }

        private static byte[] BuildPcapFile(byte[] packet, bool swap = false)
        {
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);
            // Global header: magic, major, minor, thiszone, sigfigs, snaplen, network(=1 Ethernet)
            uint magic = swap ? 0xd4c3b2a1u : 0xa1b2c3d4u;
            bw.Write(magic);
            if (swap)
            {
                bw.Write((ushort)0x0200); bw.Write((ushort)0x0400); // 2.4 swapped
                bw.Write(0); bw.Write(0); bw.Write(SwapU32(65535)); bw.Write(SwapU32(1));
            }
            else
            {
                bw.Write((ushort)2); bw.Write((ushort)4);
                bw.Write(0); bw.Write(0); bw.Write(65535u); bw.Write(1u);
            }
            // Per-packet header: ts_sec, ts_usec, incl_len, orig_len
            if (swap)
            {
                bw.Write(SwapU32(0)); bw.Write(SwapU32(0));
                bw.Write(SwapU32((uint)packet.Length)); bw.Write(SwapU32((uint)packet.Length));
            }
            else
            {
                bw.Write(0u); bw.Write(0u);
                bw.Write((uint)packet.Length); bw.Write((uint)packet.Length);
            }
            bw.Write(packet);
            return ms.ToArray();
        }

        private static uint SwapU32(uint v) =>
            ((v & 0x000000FFu) << 24) |
            ((v & 0x0000FF00u) << 8)  |
            ((v & 0x00FF0000u) >> 8)  |
            ((v & 0xFF000000u) >> 24);

        private static byte[] BuildEthernetIpv4UdpDnsAQuery(string dstIp, string qname)
        {
            // Encode qname as DNS labels with leading length and trailing 0.
            var labels = new List<byte>();
            foreach (var part in qname.Split('.'))
            {
                labels.Add((byte)part.Length);
                labels.AddRange(Encoding.ASCII.GetBytes(part));
            }
            labels.Add(0);
            // QTYPE A (1), QCLASS IN (1)
            labels.AddRange(new byte[] { 0, 1, 0, 1 });
            // DNS header: id=0x1234, flags=0x0100 (std query), qd=1, an=0, ns=0, ar=0
            var dns = new List<byte>
            {
                0x12, 0x34,
                0x01, 0x00,
                0x00, 0x01,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00,
            };
            dns.AddRange(labels);

            // UDP: src=53000, dst=53, len, csum
            int udpLen = 8 + dns.Count;
            var udp = new List<byte>
            {
                0xCF, 0x08,        // src 53000
                0x00, 0x35,        // dst 53
                (byte)((udpLen >> 8) & 0xFF), (byte)(udpLen & 0xFF),
                0x00, 0x00,        // checksum
            };
            udp.AddRange(dns);

            // IPv4: version=4 ihl=5, tos=0, total_len, id, flags, ttl=64, proto=17, csum, src 10.0.0.1, dst dstIp
            int totalLen = 20 + udp.Count;
            var ip = new List<byte>
            {
                0x45, 0x00,
                (byte)((totalLen >> 8) & 0xFF), (byte)(totalLen & 0xFF),
                0x00, 0x00,
                0x00, 0x00,
                0x40, 17,
                0x00, 0x00,
                10, 0, 0, 1,
            };
            foreach (var part in dstIp.Split('.')) ip.Add(byte.Parse(part));
            ip.AddRange(udp);

            // Ethernet: dst 6 bytes, src 6 bytes, ethertype 0x0800 (IPv4)
            var eth = new List<byte>(new byte[12]);
            eth.AddRange(new byte[] { 0x08, 0x00 });
            eth.AddRange(ip);
            return eth.ToArray();
        }

        // ───────────────────────────────────────────────────────────
        //  C20 — Auto threat-intel feed ingestion
        // ───────────────────────────────────────────────────────────

        [Fact]
        public void C20_ParsePlain_ClassifiesEachKind()
        {
            var body = string.Join("\n", new[]
            {
                "# comment line",
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", // sha256
                "deadbeefcafebabefacefeedf00dface", // md5/imphash
                "T1A0B0C0D0E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9", // tlsh-ish
                "https://evil.example/payload.exe",
                "10.0.0.7",
                "evil.example",
            });
            var ind = ThreatIntelFeedManager.ParsePlain(body);
            Assert.Contains(ind, s => s.StartsWith("sha256:",  StringComparison.Ordinal));
            Assert.Contains(ind, s => s.StartsWith("imphash:", StringComparison.Ordinal));
            Assert.Contains(ind, s => s.StartsWith("tlsh:",    StringComparison.Ordinal));
            Assert.Contains(ind, s => s.StartsWith("url:",     StringComparison.Ordinal));
            Assert.Contains(ind, s => s.StartsWith("ipv4:",    StringComparison.Ordinal));
            Assert.Contains(ind, s => s.StartsWith("domain:",  StringComparison.Ordinal));
        }

        [Fact]
        public void C20_ParseUrlhausCsv_ExtractsUrls()
        {
            // URLhaus CSV: id,dateadded,url,url_status,...
            var body =
                "#header\n" +
                "1,2024-01-01 00:00:00,https://malware.example/dropper.exe,online,...,malware,trojan,https://urlhaus.abuse.ch/url/1,reporter\n" +
                "2,2024-01-01 00:00:00,\"https://malware2.example/?x=1\",online,...,...\n";
            var ind = ThreatIntelFeedManager.ParseUrlhausCsv(body);
            Assert.Contains(ind, s => s == "url:https://malware.example/dropper.exe");
            Assert.Contains(ind, s => s == "url:https://malware2.example/?x=1");
        }

        [Fact]
        public void C20_ParseThreatFoxCsv_ExtractsTypedIocs()
        {
            // ThreatFox: first_seen,id,value,type,threat,malware,...
            var body =
                "#header\n" +
                "2024-01-01,1,1.2.3.4:80,ip:port,c2,LummaC2,...\n" +
                "2024-01-01,2,abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789,sha256_hash,payload,LummaC2,...\n" +
                "2024-01-01,3,bad.example,domain,c2,LummaC2,...\n" +
                "2024-01-01,4,https://bad.example/lp,url,c2,LummaC2,...\n";
            var ind = ThreatIntelFeedManager.ParseThreatFoxCsv(body);
            Assert.Contains(ind, s => s == "ipv4:1.2.3.4");
            Assert.Contains(ind, s => s.StartsWith("sha256:abcdef", StringComparison.Ordinal));
            Assert.Contains(ind, s => s == "domain:bad.example");
            Assert.Contains(ind, s => s == "url:https://bad.example/lp");
        }

        [Fact]
        public void C20_ParseMalwareBazaarCsv_ExtractsSha256()
        {
            // first_seen,sha256,md5,sha1,...
            var body =
                "#header\n" +
                "2024-01-01,abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789,...\n";
            var ind = ThreatIntelFeedManager.ParseMalwareBazaarCsv(body);
            Assert.Single(ind);
            Assert.Equal("sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", ind[0]);
        }

        [Fact]
        public void C20_ParseStix_ExtractsSha256AndUrl()
        {
            const string stix = """
                {
                  "type": "bundle",
                  "objects": [
                    { "type": "indicator", "pattern": "[file:hashes.'SHA-256' = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789']" },
                    { "type": "indicator", "pattern": "[url:value = 'https://evil.example/']" },
                    { "type": "malware",   "name": "decoy"  }
                  ]
                }
                """;
            var ind = ThreatIntelFeedManager.ParseStix(stix);
            Assert.Contains(ind, s => s.StartsWith("sha256:abcdef", StringComparison.Ordinal));
            Assert.Contains(ind, s => s == "url:https://evil.example/");
        }

        [Fact]
        public async Task C20_FeedManager_LoadsFromLocalFileSource_AndCachesResult()
        {
            var dir       = TmpDir();
            var feedFile  = Path.Combine(dir, "denylist.txt");
            File.WriteAllText(feedFile,
                "https://feed.example/evil1\nhttps://feed.example/evil2\n# comment\n10.0.0.1\n");
            var configJson = JsonOf(new object[]
            {
                new
                {
                    name      = "test-local",
                    format    = "plain",
                    source    = "file:///" + feedFile.Replace('\\', '/'),
                    ttl_hours = 1,
                },
            });
            var cfgPath = Path.Combine(dir, "feeds.json");
            File.WriteAllText(cfgPath, configJson);
            var cacheDir = Path.Combine(dir, "cache");

            var mgr = new ThreatIntelFeedManager(cfgPath, cacheDir);
            var summaries = await mgr.RefreshAsync(force: false, CancellationToken.None);
            Assert.Single(summaries);
            Assert.True(summaries[0].Used,    "should have fetched on first refresh");
            Assert.True(summaries[0].Loaded >= 3);
            Assert.True(File.Exists(Path.Combine(cacheDir, "test-local.idx")), "cache idx written");
            Assert.True(File.Exists(Path.Combine(cacheDir, "test-local.meta")), "cache meta written");

            Assert.Contains("https://feed.example/evil1", mgr.Pool.Urls);
            Assert.Contains("https://feed.example/evil2", mgr.Pool.Urls);
            Assert.Contains("10.0.0.1",                   mgr.Pool.Ipv4s);
        }

        [Fact]
        public void C20_FeedMatcher_ApplyAddsFeedHitsAndBumpsScore()
        {
            // Build a synthetic pool covering each kind, then call
            // Apply against an AnalysisResult that carries matching
            // sha256 / imphash / url / ip / domain values.
            var pool = new ThreatIntelFeedPool();
            pool.Sha256s.Add("ab".PadRight(64, 'a'));
            pool.Imphashes.Add("de".PadRight(32, 'd'));
            pool.Urls.Add("https://evil.example/payload");
            pool.Domains.Add("evil.example");
            pool.Ipv4s.Add("198.51.100.7");
            pool.Origin["sha256:" + "ab".PadRight(64, 'a')] = "test-feed";
            pool.Origin["imphash:" + "de".PadRight(32, 'd')] = "test-feed";
            pool.Origin["url:https://evil.example/payload"] = "test-feed";
            pool.Origin["domain:evil.example"]              = "test-feed";
            pool.Origin["ipv4:198.51.100.7"]                = "test-feed";

            var r = new AnalysisResult("/synthetic/c20-feed.bin")
            {
                Sha256  = "AB".PadRight(64, 'A'),     // intentionally upper-case
                ImpHash = "DE".PadRight(32, 'D'),
            };
            r.UrlsFound.Add("https://evil.example/payload");
            r.Ipv4Hits.Add("198.51.100.7");

            ThreatIntelFeedMatcher.Apply(r, pool);

            Assert.Contains(r.FeedHits, h => h.Contains("sha256:",  StringComparison.Ordinal));
            Assert.Contains(r.FeedHits, h => h.Contains("imphash:", StringComparison.Ordinal));
            Assert.Contains(r.FeedHits, h => h.Contains("url:",     StringComparison.Ordinal));
            Assert.Contains(r.FeedHits, h => h.Contains("domain:",  StringComparison.Ordinal));
            Assert.Contains(r.FeedHits, h => h.Contains("ipv4:",    StringComparison.Ordinal));

            int score = Analyzer.ScorePublic(r);
            // Pure-feed verdict; capped at 60 so a single feed cannot
            // drive a clean sample into HIGH on its own.
            Assert.True(score > 0,  "feed-only verdict must produce some score");
            Assert.True(score < 95, $"pure-feed verdict must remain capped below HIGH, got {score}");
            Assert.True(r.ScoreContributors.ContainsKey("Bonus:ThreatIntelFeed"));
        }

        private static string JsonOf(object[] entries)
        {
            var sb = new StringBuilder();
            sb.Append('[');
            for (int i = 0; i < entries.Length; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append(System.Text.Json.JsonSerializer.Serialize(entries[i]));
            }
            sb.Append(']');
            return sb.ToString();
        }
    }
}
