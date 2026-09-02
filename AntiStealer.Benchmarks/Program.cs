using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using AntiStealerOneExe;

namespace AntiStealer.Benchmarks;

// Section 5.8 — micro-benchmarks for the analyser's hot paths plus the
// individual stages (string extraction, AC needle scan, SHA-256). Run with:
//   dotnet run -c Release --project AntiStealer.Benchmarks -- --filter '*'
public static class Program
{
    public static void Main(string[] args) => BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
}

[MemoryDiagnoser]
public class AnalyzerBenchmarks
{
    private string _smallFile = "";
    private string _mediumFile = "";

    [GlobalSetup]
    public void Setup()
    {
        var dir = Path.Combine(Path.GetTempPath(), "antistealer-bench-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);

        _smallFile = Path.Combine(dir, "small.bin");
        File.WriteAllBytes(_smallFile, Encoding.ASCII.GetBytes("MZ" + new string('\0', 128) + "https://example.invalid"));

        _mediumFile = Path.Combine(dir, "medium.bin");
        var rng = new Random(1);
        var buf = new byte[1 * 1024 * 1024]; // 1 MB
        rng.NextBytes(buf);
        buf[0] = (byte)'M'; buf[1] = (byte)'Z';
        File.WriteAllBytes(_mediumFile, buf);
    }

    [Benchmark]
    public AnalysisResult AnalyzeSmall() => Analyzer.Analyze(_smallFile, _smallFile);

    [Benchmark]
    public AnalysisResult AnalyzeMedium() => Analyzer.Analyze(_mediumFile, _mediumFile);
}

// Section 5.8 — per-stage benchmarks. The text/imports are reused across
// runs so what we measure is the algorithm, not file IO. Useful for
// catching regressions in a single stage that the end-to-end Analyze
// benchmark would smear out.
[MemoryDiagnoser]
public class StageBenchmarks
{
    private byte[] _data = Array.Empty<byte>();
    private string _haystack = "";
    private string[] _imports = Array.Empty<string>();

    [GlobalSetup]
    public void Setup()
    {
        var rng = new Random(7);
        _data = new byte[512 * 1024];
        rng.NextBytes(_data);
        // Sprinkle in some printable ASCII strings so the extractor has
        // actual work to do; pure noise bottoms out below the min-len
        // filter and makes the bench numbers misleading.
        var samples = new[]
        {
            "https://example.invalid/a", "C:\\Users\\x\\AppData\\Roaming",
            "password=hunter2", "CryptUnprotectData", "telegram bot token",
            "discord webhook https://discordapp.com/api/webhooks/abc/def",
            "wallet.dat", "Local State", "Login Data", "metamask",
        };
        var enc = Encoding.ASCII;
        int pos = 0;
        foreach (var s in samples)
        {
            var b = enc.GetBytes(s);
            if (pos + b.Length + 8 > _data.Length) break;
            _data[pos++] = 0;
            Array.Copy(b, 0, _data, pos, b.Length);
            pos += b.Length;
            _data[pos++] = 0;
        }

        _haystack = string.Join('\n', samples);
        _imports = new[]
        {
            "CryptUnprotectData", "InternetOpenA", "BCryptDecrypt",
            "WSAStartup", "GetAdaptersAddresses", "OpenProcess",
            "ReadProcessMemory", "VirtualAllocEx", "CreateRemoteThread",
            "GetAsyncKeyState", "RegOpenKeyExA", "CreateFileW",
        };
    }

    [Benchmark]
    public int Needles_SuspiciousString_AhoCorasick()
        => Needles.SuspiciousStringAc.Value.FindUniquePatterns(_haystack).Count;

    [Benchmark]
    public int Needles_SuspiciousApi_AhoCorasick()
        => Needles.MatchSuspiciousApis(_imports).Count;

    [Benchmark]
    public int Sha256_512KB()
    {
        using var sha = System.Security.Cryptography.SHA256.Create();
        return sha.ComputeHash(_data).Length;
    }
}
