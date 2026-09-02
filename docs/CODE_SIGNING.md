# Code-signing AntiStealer.exe (GG7)

AntiStealer ships as a single-file Windows executable. To avoid SmartScreen warnings and let customers verify the binary's origin, you should sign every release build with an **EV (Extended Validation) code-signing certificate** from a CA such as DigiCert, Sectigo, or Certum.

> You can ship unsigned builds for development/testing, but enterprise customers will refuse to deploy anything that isn't signed by a trusted CA.

## One-time setup

1. Purchase an EV code-signing certificate. You will receive a FIPS-140-2 hardware token (USB HSM). **The private key never leaves the token**; signing has to happen on a machine where the token is plugged in.
2. Install the token drivers (SafeNet Authentication Client, YubiHSM, etc.).
3. Install the Windows 10/11 SDK — provides `signtool.exe`.
4. Optionally, register for an **Azure Trusted Signing** account if you want cloud-hosted signing instead of a physical token.

## Signing a release

```powershell
# Assuming a single-file publish into ./publish/win-x64/AntiStealer.exe
$exe = "publish\win-x64\AntiStealer.exe"

signtool sign `
    /fd SHA256 `
    /td SHA256 `
    /tr http://timestamp.digicert.com `
    /n "Your Company Name, Ltd."  `  # or /sha1 <thumbprint>
    /d "AntiStealer" `
    /du "https://antistealer.example/"  `
    $exe

signtool verify /pa /v $exe
```

If you have more than one publish target (`win-x64`, `win-x86`, `win-arm64`) repeat for each.

## Automation in CI

Signing in CI requires access to either:

- A self-hosted runner with the HSM plugged in (recommended for EV).
- Azure Trusted Signing (cloud) — use the `Azure/trusted-signing-action@v0.5.0` GitHub Action.

Example GitHub Actions step:

```yaml
- name: Sign binary
  uses: azure/trusted-signing-action@v0.5.0
  with:
    azure-tenant-id:        ${{ secrets.AZURE_TENANT_ID }}
    azure-client-id:        ${{ secrets.AZURE_CLIENT_ID }}
    azure-client-secret:    ${{ secrets.AZURE_CLIENT_SECRET }}
    endpoint:               https://eus.codesigning.azure.net/
    trusted-signing-account-name: antistealer-signing
    certificate-profile-name:     antistealer-release
    files-folder:           publish\win-x64\
    file-digest:            SHA256
    timestamp-rfc3161:      http://timestamp.acs.microsoft.com
    timestamp-digest:       SHA256
```

**Secrets required:** `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` for a service principal that has *Trusted Signing Certificate Profile Signer* on the certificate profile.

## Manifest

The `AntiStealerOneExe.exe.manifest` is already configured with `requestedExecutionLevel level="asInvoker"` so the exe does NOT trigger a UAC elevation dialog. Do not change this unless you add functionality that genuinely requires administrator rights.

## Publishing

Once signed, upload the binary and its detached SHA-256 to your release channel. Clients verify with:

```powershell
Get-FileHash .\AntiStealer.exe -Algorithm SHA256
signtool verify /pa /v .\AntiStealer.exe
```

Both must succeed.
