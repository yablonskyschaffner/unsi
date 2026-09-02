# AntiStealer — detection rules

AntiStealer ships with three rule engines that users can extend without rebuilding:

| Folder | Engine | Format | Selector |
|---|---|---|---|
| `sigma/` | BB1 Sigma-full | YAML (`.yml` / `.yaml`) | Substrings against extracted strings/URLs |
| `capa/`  | BB2 CAPA-ish   | Plain text (`.capa` / `.rule`) | Imported APIs + optional strings |
| `yara/`  | B1  YARA       | `.yar` (invoked via external `yara` / `yara64`) | Full YARA |

## Lookup order

1. `%APPDATA%\AntiStealer\rules\<engine>\*` — per-user, survives upgrades
2. `<exe-dir>\rules\<engine>\*` — shipped with the installer / unzipped build

## Sigma-full (BB1)

Minimal subset of the Sigma spec — enough for strong static-string rules without requiring
a full sigmac toolchain.

```yaml
title: Stealer — Telegram exfil
detection:
  selection:
    - "api.telegram.org/bot"
    - "sendMessage"
    - "%s"
  condition: selection
```

Supported `condition:` operators: `all of <sel>`, `1 of <sel>`, `<sel1> and <sel2>`,
`<sel1> or <sel2>`, `not <sel>`.

## CAPA-ish (BB2)

```text
capability: monitors and modifies the clipboard
match: all           # or "any"
imports:
  - OpenClipboard
  - GetClipboardData
  - SetClipboardData
strings:             # optional; all listed strings must be present
  - clipboard
```

The `match: all` (default) requires every listed import to be present; `match: any` fires on
the first match. If `strings:` is present, every string must also be present.

## YARA

Drop `.yar` files here; AntiStealer invokes the system `yara` binary (or `yara64.exe` on
Windows) against each scanned file. Hits are attributed to `rule_name [basename.yar]`.
