using System.Text.RegularExpressions;
using System.Collections.Concurrent;

// FF1–FF9: performance utilities.
//
// This module is deliberately dependency-free. It provides:
//
//   FF2  AhoCorasick            — multi-pattern substring matcher, O(n + sum|pi|)
//                                 setup, O(n + k) match. Drop-in replacement
//                                 for foreach(needle) { text.Contains(needle) }.
//
//   FF3  CompiledRegex.Get(...) — process-wide cache of `RegexOptions.Compiled`
//                                 regexes. Avoids re-JITting the same pattern.
//
//   FF4  FileResultCache        — JSON-per-SHA256 cache of AnalysisResults
//                                 under %LOCALAPPDATA%\AntiStealer\cache\.
//                                 Skip re-scanning files we've already analyzed.
//
//   FF5  IncrementalHash.Sha256AndPrefix
//                                — compute SHA256 and capture the first N
//                                  bytes in a single stream read.
//
//   FF6  BigFileStream          — wraps a FileStream for samples > 50 MB;
//                                 returned Span is a read-only view backed by
//                                 ArrayPool<byte>. No giant LOH allocations.
//
//   FF9  PerfCounters           — lightweight per-module timings surfaced in
//                                 the report "== Performance =="; no external
//                                 profiling needed.

namespace AntiStealerOneExe
{
    // -----------------------------------------------------------------
    // FF2 — Aho-Corasick multi-pattern matcher
    // -----------------------------------------------------------------
    public sealed class AhoCorasick
    {
        private sealed class Node
        {
            public readonly Dictionary<char, Node> Next = new();
            public Node? Fail;
            public readonly List<string> Outputs = new();
        }

        private readonly Node _root = new();

        public AhoCorasick(IEnumerable<string> patterns, bool ignoreCase = false)
        {
            foreach (var p in patterns)
            {
                if (string.IsNullOrEmpty(p)) continue;
                var cur = _root;
                foreach (var ch in ignoreCase ? p.ToLowerInvariant() : p)
                {
                    if (!cur.Next.TryGetValue(ch, out var nxt))
                    {
                        nxt = new Node();
                        cur.Next[ch] = nxt;
                    }
                    cur = nxt;
                }
                cur.Outputs.Add(p);
            }

            // BFS to set failure links.
            var queue = new Queue<Node>();
            foreach (var kv in _root.Next)
            {
                kv.Value.Fail = _root;
                queue.Enqueue(kv.Value);
            }
            while (queue.Count > 0)
            {
                var cur = queue.Dequeue();
                foreach (var kv in cur.Next)
                {
                    var ch   = kv.Key;
                    var nxt  = kv.Value;
                    var fail = cur.Fail;
                    while (fail != null && !fail.Next.ContainsKey(ch)) fail = fail.Fail;
                    nxt.Fail = fail?.Next.GetValueOrDefault(ch) ?? _root;
                    if (nxt.Fail == nxt) nxt.Fail = _root;
                    if (nxt.Fail != null) nxt.Outputs.AddRange(nxt.Fail.Outputs);
                    queue.Enqueue(nxt);
                }
            }
            IgnoreCase = ignoreCase;
        }

        public bool IgnoreCase { get; }

        // Returns a list of (index, pattern) pairs for every match in `text`.
        public List<(int Index, string Pattern)> FindAll(string text)
        {
            var hits = new List<(int, string)>();
            var cur = _root;
            for (int i = 0; i < text.Length; i++)
            {
                char ch = IgnoreCase ? char.ToLowerInvariant(text[i]) : text[i];
                while (cur != _root && !cur.Next.ContainsKey(ch)) cur = cur.Fail ?? _root;
                if (cur.Next.TryGetValue(ch, out var next)) cur = next;
                foreach (var p in cur.Outputs)
                    hits.Add((i - p.Length + 1, p));
            }
            return hits;
        }

        // Convenience: just the set of patterns present.
        public HashSet<string> FindUniquePatterns(string text)
        {
            var set = new HashSet<string>();
            var cur = _root;
            for (int i = 0; i < text.Length; i++)
            {
                char ch = IgnoreCase ? char.ToLowerInvariant(text[i]) : text[i];
                while (cur != _root && !cur.Next.ContainsKey(ch)) cur = cur.Fail ?? _root;
                if (cur.Next.TryGetValue(ch, out var next)) cur = next;
                foreach (var p in cur.Outputs) set.Add(p);
            }
            return set;
        }
    }

    // -----------------------------------------------------------------
    // FF3 — Compiled-regex cache
    // -----------------------------------------------------------------
    public static class CompiledRegex
    {
        private static readonly ConcurrentDictionary<(string pattern, RegexOptions opts), Regex> Cache = new();

        public static Regex Get(string pattern, RegexOptions options = RegexOptions.None)
        {
            options |= RegexOptions.Compiled;
            return Cache.GetOrAdd((pattern, options), k => new Regex(k.pattern, k.opts,
                TimeSpan.FromMilliseconds(500)));
        }
    }

    // -----------------------------------------------------------------
    // FF4 — JSON-per-SHA256 result cache
    // -----------------------------------------------------------------
    public static class FileResultCache
    {
        public static string CacheRoot { get; set; } =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                         "AntiStealer", "cache");

        public static bool TryGet(string sha256, out string json)
        {
            json = "";
            if (string.IsNullOrEmpty(sha256) || sha256.Length != 64) return false;
            var path = Path.Combine(CacheRoot, sha256.Substring(0, 2), sha256 + ".json");
            if (!File.Exists(path)) return false;
            try { json = File.ReadAllText(path); return true; }
            catch { return false; }
        }

        public static void Put(string sha256, string json)
        {
            if (string.IsNullOrEmpty(sha256) || sha256.Length != 64) return;
            try
            {
                var dir = Path.Combine(CacheRoot, sha256.Substring(0, 2));
                Directory.CreateDirectory(dir);
                File.WriteAllText(Path.Combine(dir, sha256 + ".json"), json);
            }
            catch { /* best-effort cache */ }
        }

        public static void Clear()
        {
            try { if (Directory.Exists(CacheRoot)) Directory.Delete(CacheRoot, true); }
            catch { }
        }
    }

    // -----------------------------------------------------------------
    // FF5 — one-pass SHA256 + first-N bytes
    // -----------------------------------------------------------------
    public static class SampleHasher
    {
        public static (string Sha256, byte[] Prefix) Sha256AndPrefix(string path, int prefixLen)
        {
            using var sha = System.Security.Cryptography.SHA256.Create();
            using var fs  = File.OpenRead(path);
            var prefix = new byte[Math.Min(prefixLen, (int)fs.Length)];
            int prefixIdx = 0;
            var buffer = new byte[64 * 1024];
            int read;
            while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
            {
                sha.TransformBlock(buffer, 0, read, null, 0);
                int copy = Math.Min(read, prefix.Length - prefixIdx);
                if (copy > 0)
                {
                    Buffer.BlockCopy(buffer, 0, prefix, prefixIdx, copy);
                    prefixIdx += copy;
                }
            }
            sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            return (HexUtil.ToLowerHex(sha.Hash!), prefix);
        }
    }

    // -----------------------------------------------------------------
    // FF9 — perf counters
    // -----------------------------------------------------------------
    public static class PerfCounters
    {
        private static readonly ConcurrentDictionary<string, long> Totals   = new();
        private static readonly ConcurrentDictionary<string, long> Counts   = new();

        public readonly struct Scope : IDisposable
        {
            private readonly string _name;
            private readonly long _start;
            public Scope(string name) { _name = name; _start = System.Diagnostics.Stopwatch.GetTimestamp(); }
            public void Dispose()
            {
                long ticks = System.Diagnostics.Stopwatch.GetTimestamp() - _start;
                Totals.AddOrUpdate(_name, ticks, (_, v) => v + ticks);
                Counts.AddOrUpdate(_name, 1,     (_, v) => v + 1);
            }
        }

        public static Scope Time(string name) => new(name);

        public static string Render()
        {
            if (Totals.IsEmpty) return "";
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("== Performance ==");
            double freq = System.Diagnostics.Stopwatch.Frequency;
            foreach (var kv in Totals.OrderByDescending(x => x.Value))
            {
                double ms = kv.Value * 1000.0 / freq;
                long   n  = Counts.TryGetValue(kv.Key, out var c) ? c : 0;
                sb.AppendLine($"  {kv.Key,-36} {ms,10:F2} ms   x{n}");
            }
            return sb.ToString();
        }

        public static void Reset()
        {
            Totals.Clear();
            Counts.Clear();
        }
    }
}
