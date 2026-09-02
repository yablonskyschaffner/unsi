// PR 15 — Section 4 — Stages P5 + P6: relationship / parent-child
// correlation graph.
//
// A growing fraction of stealer deliveries is multi-file: a signed
// EXE next to an unsigned DLL with a system name (DLL side-loading
// bait), a Lua loader plus a native .asi / .dll payload, a ZIP
// that contains both an MoonLoader script and a Themida-protected
// .asi inside the same bundle. Pure per-file scoring misses these
// — none of the parts is "definitively malicious" on its own, but
// the combination is.
//
// This module runs after the analyzer has already scored the
// parent and every child (A4 / B7 archive recursion already
// populates r.Children) and writes a list of structured
// RelationshipEvidence records on the parent. Each record is
// later surfaced in the report and folded into the capability
// graph (P10).
//
// The decisive floors that come out of P11 / Score() also key off
// the relationship edges set here.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace AntiStealerOneExe
{
    /// <summary>
    /// A single parent-child relationship edge.
    /// </summary>
    public sealed class RelationshipEdge
    {
        /// <summary>
        /// Edge kind: <c>lua-downloads-dll</c>,
        /// <c>archive-contains-loader-and-payload</c>,
        /// <c>signed-exe-loads-nearby-dll</c>,
        /// <c>exe-and-sideload-target-dll</c>, ...
        /// </summary>
        public string Kind   { get; set; } = string.Empty;
        public string From   { get; set; } = string.Empty;
        public string To     { get; set; } = string.Empty;
        public string Reason { get; set; } = string.Empty;
    }

    public sealed partial class AnalysisResult
    {
        // P5 — parent-child correlation edges. Populated by
        // RelationshipAnalyzer.Build() after Children[] is filled.
        public List<RelationshipEdge> RelationshipEvidence { get; set; } = new();
    }

    public static class RelationshipAnalyzer
    {
        // Names of system DLLs that are typical side-load targets.
        // A signed EXE next to an unsigned DLL with one of these
        // names is a strong DLL-side-loading bait pattern (P6).
        private static readonly HashSet<string> SideloadTargets =
            new(StringComparer.OrdinalIgnoreCase)
        {
            "version.dll", "winmm.dll", "winhttp.dll",
            "dwmapi.dll",  "wtsapi32.dll", "msimg32.dll",
            "dbghelp.dll", "cryptbase.dll", "d3dcompiler_47.dll",
            "d3d9.dll",    "dinput8.dll", "secur32.dll",
            "msvcr120.dll","msvcr100.dll","mscoree.dll",
            "iphlpapi.dll","userenv.dll","propsys.dll",
            "fwpuclnt.dll",
        };

        // Native payload extensions a Lua loader typically pulls
        // down (matches LuaDetectors.LuaNativePayloadExts).
        private static readonly HashSet<string> NativePayloadExts =
            new(StringComparer.OrdinalIgnoreCase)
        {
            ".asi", ".dll", ".exe", ".saa",
        };

        // -----------------------------------------------------------------

        /// <summary>
        /// Build the relationship graph on top of the already-scored
        /// parent + children. Idempotent — re-running it fully
        /// rebuilds RelationshipEvidence on the parent.
        /// </summary>
        public static void Build(AnalysisResult parent)
        {
            if (parent == null) return;
            parent.RelationshipEvidence.Clear();

            // No children means nothing to correlate. We still
            // produce edges for the "this file IS a Lua loader for
            // a DLL named in its own download URLs" sub-case
            // below, but most of the heavy lifting requires
            // siblings.
            var children = parent.Children ?? new List<AnalysisResult>();

            // Pre-collect bookkeeping.
            var nativeChildren = children
                .Where(IsNativePayload).ToList();
            var luaChildren    = children
                .Where(IsLuaLoader).ToList();
            var signedExeChildren = children
                .Where(c => c != null && c.IsExe && c.IsSigned).ToList();
            var unsignedDllChildren = children
                .Where(c => c != null && c.IsDll && !c.IsSigned).ToList();

            // ---------------------------------------------------
            // P5.a — archive-contains-loader-and-payload.
            //
            //     A single archive carries BOTH a Lua loader and a
            //     native payload (.asi / .dll / .exe / .saa). This
            //     is the canonical SA-MP / MoonLoader stealer
            //     delivery shape.
            // ---------------------------------------------------
            foreach (var lua in luaChildren)
            foreach (var nat in nativeChildren)
            {
                parent.RelationshipEvidence.Add(new RelationshipEdge
                {
                    Kind   = "archive-contains-loader-and-payload",
                    From   = lua.FilePath ?? string.Empty,
                    To     = nat.FilePath ?? string.Empty,
                    Reason = "lua-loader+native-payload-in-same-archive",
                });
            }

            // ---------------------------------------------------
            // P5.b — lua-downloads-dll.
            //
            //     The Lua child fired the L8 download-and-load
            //     chain marker AND a sibling native payload is
            //     present in the archive.  This is the strongest
            //     form of the relationship (Lua -> native loader),
            //     used by Score() to floor the parent at 92.
            // ---------------------------------------------------
            foreach (var lua in luaChildren.Where(l => l.LuaDownloadAndLoadChain))
            foreach (var nat in nativeChildren)
            {
                parent.RelationshipEvidence.Add(new RelationshipEdge
                {
                    Kind   = "lua-downloads-dll",
                    From   = lua.FilePath ?? string.Empty,
                    To     = nat.FilePath ?? string.Empty,
                    Reason = "L8-chain-on-loader+native-sibling",
                });

                // Lift the chain marker onto the parent so the
                // P11 floor (which reads parent.LuaDownloadAndLoadChain)
                // can fire even when the parent itself is the
                // archive, not the Lua file.
                parent.LuaDownloadAndLoadChain = true;
            }

            // ---------------------------------------------------
            // P6 — EXE + side-load-target DLL pair.
            //
            //     A signed EXE next to an unsigned DLL whose name
            //     matches a known side-load target is a strong
            //     hijack-bait pattern.  Also covers the case
            //     where the DLL's name appears in the EXE's
            //     ImportedApis (host imports it).
            // ---------------------------------------------------
            foreach (var exe in signedExeChildren)
            foreach (var dll in unsignedDllChildren)
            {
                var dllName = SafeFileName(dll.FilePath);
                if (string.IsNullOrEmpty(dllName)) continue;

                bool isSystemSideloadName = SideloadTargets.Contains(dllName);
                bool isImportedByHost =
                    exe.ImportedApis != null &&
                    exe.ImportedApis.Any(api =>
                        dllName.Equals(api, StringComparison.OrdinalIgnoreCase));
                if (!isSystemSideloadName && !isImportedByHost) continue;

                parent.RelationshipEvidence.Add(new RelationshipEdge
                {
                    Kind   = isSystemSideloadName
                                 ? "exe-and-sideload-target-dll"
                                 : "signed-exe-loads-nearby-dll",
                    From   = exe.FilePath ?? string.Empty,
                    To     = dll.FilePath ?? string.Empty,
                    Reason = isSystemSideloadName
                                 ? $"sideload-target:{dllName}"
                                 : $"import-name:{dllName}",
                });
            }

            // ---------------------------------------------------
            // P5.c — protected native payload in an ASI / .dll
            //         child. Surfaces explicitly so the UI can
            //         show "Themida-protected DLL bundled with a
            //         Lua loader" without re-reading every child.
            // ---------------------------------------------------
            foreach (var nat in nativeChildren)
            {
                if (nat.Protection is { IsProtected: true })
                {
                    parent.RelationshipEvidence.Add(new RelationshipEdge
                    {
                        Kind   = "protected-native-child",
                        From   = parent.FilePath ?? string.Empty,
                        To     = nat.FilePath ?? string.Empty,
                        Reason = nat.Protection.ProtectorGuess ?? "protected",
                    });
                }
            }
        }

        // -----------------------------------------------------------------

        private static bool IsNativePayload(AnalysisResult c)
        {
            if (c == null) return false;
            if (string.Equals(c.FormatFamily, "PE-DLL-ASI",
                              StringComparison.OrdinalIgnoreCase)) return true;
            if (string.Equals(c.FormatFamily, "PE-DLL",
                              StringComparison.OrdinalIgnoreCase)) return true;
            if (string.Equals(c.FormatFamily, "PE-EXE",
                              StringComparison.OrdinalIgnoreCase)) return true;
            // Fall back on extension for results that didn't go
            // through the PE parser (e.g. children produced by
            // archive listing without a deep analyse pass).
            var ext = SafeExtension(c.FilePath);
            return NativePayloadExts.Contains(ext);
        }

        private static bool IsLuaLoader(AnalysisResult c)
        {
            if (c == null) return false;
            if (string.Equals(c.FormatFamily, "Script-LUA",
                              StringComparison.OrdinalIgnoreCase)) return true;
            if (string.Equals(c.FormatFamily, "Lua-Bytecode",
                              StringComparison.OrdinalIgnoreCase)) return true;
            var ext = SafeExtension(c.FilePath);
            return ext == ".lua" || ext == ".luac";
        }

        private static string SafeExtension(string? path)
        {
            if (string.IsNullOrEmpty(path)) return string.Empty;
            try { return Path.GetExtension(path) ?? string.Empty; }
            catch { return string.Empty; }
        }

        private static string SafeFileName(string? path)
        {
            if (string.IsNullOrEmpty(path)) return string.Empty;
            try { return Path.GetFileName(path) ?? string.Empty; }
            catch { return string.Empty; }
        }
    }
}
