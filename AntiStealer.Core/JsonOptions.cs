// Section 22.7 — centralised, thread-safe JsonSerializerOptions instances.
//
// JsonSerializerOptions is documented as thread-safe once it has been used and
// the source generator has been resolved — but allocating a fresh instance per
// serialize call (as the legacy code did in 6+ places) defeats the metadata
// cache and adds GC pressure. These two singletons cover the only two shapes
// the codebase uses today: indented (for human-readable reports / settings) and
// camelCase indented (for licence / API blobs).
using System.Text.Json;

namespace AntiStealerOneExe
{
    public static class JsonOptionsRegistry
    {
        // Pretty-printed, default property naming. Mirrors `new JsonSerializerOptions { WriteIndented = true }`.
        public static readonly JsonSerializerOptions Indented = new()
        {
            WriteIndented = true,
        };

        // Pretty-printed, camelCase property names. Mirrors the licence-blob options used in
        // Commercial.LicenseVerifier / docs/COMMERCIAL.md.
        public static readonly JsonSerializerOptions CamelCaseIndented = new()
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        };

        // CamelCase + non-indented (parser/wire format).
        public static readonly JsonSerializerOptions CamelCase = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        };
    }
}
