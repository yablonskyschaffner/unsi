# AntiStealer — Commercial SKUs

AntiStealer ships in three tiers. All tiers share the same detection engine; tiers differ only in **feature gating**, concurrency limits, and support.

## SKUs

| Feature                               | Community (free) | Pro                | Enterprise            |
|---------------------------------------|------------------|--------------------|-----------------------|
| Single-file scan (GUI + CLI)          | yes              | yes                | yes                   |
| Reports: JSON / HTML / Markdown       | yes              | yes                | yes                   |
| Reports: PDF / SARIF / STIX / MISP    | —                | yes                | yes                   |
| Reports: CEF / Syslog / OpenIOC       | —                | yes                | yes                   |
| Batch folder scan                     | yes (≤ 100 files)| yes                | yes                   |
| Archive scanning (ZIP / 7z / etc)     | yes              | yes                | yes                   |
| REST API (`POST /scan`, `GET /health`) | —                | yes (localhost)    | yes (any bind)        |
| Watch-folder / Windows Service        | —                | —                  | yes                   |
| Custom YARA / Sigma / CAPA rules      | bundled only     | user + bundled     | user + bundled + feed |
| Cloud enrichment (VT, MB, URLhaus…)   | with your keys   | with your keys     | with your keys        |
| Auto-update channel                   | stable           | stable + beta      | dedicated             |
| License seats                         | 1                | 1 per license      | org-wide              |
| Support                               | community (issues)| email, 48 h SLA    | email + phone, 4 h SLA |

## License format

A license is a JSON document signed with a vendor HMAC-SHA256 key. The client carries the vendor public-key and validates **offline** (no phone-home).

```json
{
  "customer": "Acme Corp",
  "sku": "pro",
  "issued":  "2026-01-15T00:00:00Z",
  "expires": "2027-01-15T00:00:00Z",
  "seats":  25,
  "features": ["scan", "report", "rest", "pdf", "misp"],
  "signature": "HEX-HMAC-SHA256"
}
```

### Generating a license (vendor side)

```csharp
using AntiStealerOneExe;

var lic = new License
{
    Customer = "Acme Corp",
    Sku = "pro",
    Issued   = DateTime.UtcNow,
    Expires  = DateTime.UtcNow.AddYears(1),
    Seats    = 25,
    Features = new List<string> { "scan", "report", "rest", "pdf", "misp" },
};
LicenseVerifier.Sign(lic, System.Environment.GetEnvironmentVariable("ANTISTEALER_LICENSE_KEY")!);
File.WriteAllText("acme.license.json",
    JsonSerializer.Serialize(lic, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true }));
```

The HMAC secret must be set via the `ANTISTEALER_LICENSE_KEY` environment variable during license generation. Store it only on the signing machine (offline) — it is the crown jewel of the licensing system.

### Using a license (customer side)

CLI:

```
AntiStealer.exe --license acme.license.json scan ./downloads
```

GUI:

```
File → Activate License → acme.license.json
```

The license is validated on every launch. An invalid, expired, or tampered license causes the app to fall back to the **Community** feature set.

## Update channel

Releases are published as a signed manifest at `https://releases.example.com/antistealer/latest.json`:

```json
{
  "version": "1.2.0",
  "released": "2026-02-14T12:00:00Z",
  "sha256": "…",
  "url": "https://releases.example.com/antistealer/1.2.0/AntiStealer.exe",
  "notes": "Added CC11, BB27 improvements.",
  "signature": "HEX-HMAC-SHA256"
}
```

The client fetches the manifest on startup (once per 24 h), verifies the HMAC, and, if `version > ProductInfo.Version`, shows an **"Update available"** notification. Actual download-and-replace is user-confirmed.

## Getting started

```
# Free community build
dotnet publish AntiStealerOneExe -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true

# Or download from the Releases page
```

For Pro / Enterprise pricing and licensing, email `sales@antistealer.example` or open a discussion at <https://github.com/whysgit/antistealer/discussions>.
