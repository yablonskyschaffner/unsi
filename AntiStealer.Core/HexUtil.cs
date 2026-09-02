using System;

namespace AntiStealerOneExe
{
    /// <summary>
    /// Section 22.1 — single helper for hex-encoding byte buffers as
    /// lowercase strings. Centralises what used to be scattered
    /// <c>Convert.ToHexString(b).ToLowerInvariant()</c> calls so we can swap
    /// the implementation in one place if .NET ever ships
    /// <c>Convert.ToHexStringLower</c> on net8.0 (today it's only on net9.0+).
    /// </summary>
    public static class HexUtil
    {
        /// <summary>
        /// Encode <paramref name="bytes"/> as a lowercase hex string (no
        /// separators, no <c>0x</c> prefix). Equivalent to
        /// <c>BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant()</c>
        /// but allocation-light: <c>Convert.ToHexString</c> writes directly to a
        /// preallocated buffer, then <c>String.ToLowerInvariant</c> walks it.
        /// </summary>
        public static string ToLowerHex(ReadOnlySpan<byte> bytes)
            => Convert.ToHexString(bytes).ToLowerInvariant();

        /// <summary>Same as <see cref="ToLowerHex(ReadOnlySpan{byte})"/>.</summary>
        public static string ToLowerHex(byte[] bytes)
            => Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
