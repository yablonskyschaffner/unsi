// Starter YARA rules for common stealer families.
// These are deliberately CONSERVATIVE — just public-string anchors, not private yara-x trickery.
// Copy this folder to:   %APPDATA%\AntiStealer\yara\    or next to AntiStealer.exe as ./yara-rules/
// AntiStealer will invoke `yara64.exe` / `yara.exe` (whichever is on PATH or next to the exe)
// against each .yar file on every scanned sample.

rule Stealer_Generic_BrowserDbs
{
    meta:
        author = "antistealer"
        description = "Generic browser-stealer artifact names"
    strings:
        $a1 = "Login Data"           ascii wide
        $a2 = "Web Data"             ascii wide
        $a3 = "Cookies-journal"      ascii wide
        $a4 = "Network\\Cookies"     ascii wide
        $a5 = "os_crypt"             ascii wide
        $a6 = "encrypted_key"        ascii wide
    condition:
        2 of ($a*)
}

rule Stealer_RedLine_Markers
{
    meta:
        author = "antistealer"
        description = "RedLine stealer string markers (public)"
    strings:
        $r1 = "RedLine"              ascii wide
        $r2 = "SELECT origin_url, username_value, password_value FROM logins" ascii wide
        $r3 = "ScanningArgs"         ascii wide
        $r4 = "GetScanResult"        ascii wide
    condition:
        2 of them
}

rule Stealer_Vidar_Markers
{
    meta:
        author = "antistealer"
        description = "Vidar / Arkei stealer markers (public)"
    strings:
        $v1 = "ProgramData\\VCRuntime" ascii wide
        $v2 = "vcruntime140.dll"       ascii wide
        $v3 = "Vidar"                  ascii wide
        $v4 = "screenshot.jpg"         ascii wide
        $v5 = "information.txt"        ascii wide
    condition:
        3 of them
}

rule Stealer_Lumma_Markers
{
    meta:
        author = "antistealer"
        description = "Lumma stealer markers (public)"
    strings:
        $l1 = "LummaC2" ascii wide
        $l2 = "Lumma"   ascii wide
        $l3 = "zRJqU"   ascii wide
        $l4 = "get_hw_id" ascii wide
    condition:
        2 of them
}

rule Stealer_Raccoon_Markers
{
    meta:
        author = "antistealer"
        description = "Raccoon v1/v2 stealer markers"
    strings:
        $r1 = "RC2.0" ascii wide
        $r2 = "/gate/log.php" ascii wide
        $r3 = "machineId=" ascii wide
        $r4 = "configId=" ascii wide
    condition:
        2 of them
}

rule Stealer_StealC_Markers
{
    meta:
        author = "antistealer"
        description = "StealC stealer markers"
    strings:
        $s1 = "StealC" ascii wide
        $s2 = "/server/gate" ascii wide
        $s3 = "hwid="          ascii wide
        $s4 = "BuildId="       ascii wide
    condition:
        2 of them
}

rule Anti_Analysis_VM_Names
{
    meta:
        author = "antistealer"
        description = "VM / sandbox tool name references"
    strings:
        $v1 = "VBoxService.exe"  ascii wide
        $v2 = "VBoxTray.exe"     ascii wide
        $v3 = "VMTools"          ascii wide
        $v4 = "prl_tools"        ascii wide
        $v5 = "SbieDll.dll"      ascii wide
        $v6 = "Sandboxie"        ascii wide
        $v7 = "Cuckoo"           ascii wide
    condition:
        2 of them
}

rule Crypto_Wallet_Files
{
    meta:
        author = "antistealer"
        description = "Desktop crypto-wallet file artifacts"
    strings:
        $w1 = "wallet.dat"      ascii wide
        $w2 = "Local Storage\\leveldb" ascii wide
        $w3 = "Exodus"          ascii wide
        $w4 = "Atomic"          ascii wide
        $w5 = "MetaMask"        ascii wide
        $w6 = "Electrum"        ascii wide
    condition:
        2 of them
}
