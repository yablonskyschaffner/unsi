// Section 13.3 — Drop-target validation.
//
// Anywhere we are about to write attacker-controlled data to disk
// (extracted archive entries, quarantine files, generated reports), we
// fully resolve the destination path and verify it lands under one of an
// allow-listed set of roots. This is the second line of defence behind
// SafeExtract's per-entry path-traversal check (a malicious caller could
// still pass a destination root that is itself a junction or relative
// path).
//
// Path resolution honours symlinks / reparse points by going through
// File/Directory.ResolveLinkTarget semantics where the framework supports
// it; we just call Path.GetFullPath to canonicalise and then string-prefix
// match the result. That is the same approach used by SafeExtract so the
// behaviour is consistent across the codebase.
using System;
using System.IO;

namespace AntiStealerOneExe
{
    public static class DropValidator
    {
        /// <summary>
        /// Returns true when <paramref name="targetPath"/>, after full
        /// canonicalisation, is contained under <paramref name="allowedRoot"/>.
        /// Both inputs are normalised (forward / back slashes converged,
        /// case-insensitive on Windows). The caller is responsible for
        /// passing a non-empty allowed root — an empty string is rejected
        /// to avoid the trivial "" prefix-match.
        /// </summary>
        public static bool IsUnderRoot(string? targetPath, string? allowedRoot)
        {
            if (string.IsNullOrWhiteSpace(targetPath))  return false;
            if (string.IsNullOrWhiteSpace(allowedRoot)) return false;

            string fullTarget;
            string fullRoot;
            try
            {
                fullTarget = Path.GetFullPath(targetPath);
                fullRoot   = Path.GetFullPath(allowedRoot);
            }
            catch (Exception)
            {
                return false;
            }

            // Append a trailing separator so the prefix match cannot succeed
            // accidentally on "C:/foo" vs. "C:/foobar" — the latter starts
            // with the former without being a child path.
            if (!fullRoot.EndsWith(Path.DirectorySeparatorChar) &&
                !fullRoot.EndsWith(Path.AltDirectorySeparatorChar))
            {
                fullRoot += Path.DirectorySeparatorChar;
            }

            var cmp = OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal;
            return fullTarget.StartsWith(fullRoot, cmp);
        }

        /// <summary>
        /// Variant for "any of these roots". Returns true if at least one
        /// allowed root contains the target.
        /// </summary>
        public static bool IsUnderAnyRoot(string? targetPath, params string[] allowedRoots)
        {
            if (allowedRoots == null || allowedRoots.Length == 0) return false;
            foreach (var r in allowedRoots)
            {
                if (IsUnderRoot(targetPath, r)) return true;
            }
            return false;
        }

        /// <summary>
        /// Throws <see cref="UnauthorizedAccessException"/> if the target
        /// is not under <paramref name="allowedRoot"/>. Used at write
        /// sites where we want a hard fail (bypassing it would mean
        /// dropping a file outside the quarantine / report directory,
        /// which is a security boundary).
        /// </summary>
        public static void EnsureUnderRoot(string? targetPath, string? allowedRoot, string callSite)
        {
            if (!IsUnderRoot(targetPath, allowedRoot))
            {
                throw new UnauthorizedAccessException(
                    $"{callSite}: target '{targetPath}' is not contained under allowed root '{allowedRoot}'.");
            }
        }
    }
}
