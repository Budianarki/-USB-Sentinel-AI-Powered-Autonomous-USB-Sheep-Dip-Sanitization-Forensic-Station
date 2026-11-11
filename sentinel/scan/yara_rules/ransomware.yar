/*
  USB Sentinel - YARA Rules: Ransomware & Destruction Vectors
  Modeled on LockBit 3.0, WannaCry, Stop/Djvu, and Volume Shadow Copy wiping techniques.
*/

rule LockBit_Ransomware_Indicators {
    meta:
        description = "Detects LockBit 2.0 / 3.0 Black ransomware strings and defense evasion commands"
        author = "USB Sentinel Threat Intelligence"
        family = "LockBit"
        reference = "https://bazaar.abuse.ch/browse/tag/LockBit/"
        severity = "CRITICAL"
        threat_type = "Ransomware"

    strings:
        $str1 = "LockBit" nocase
        $str2 = ".lockbit" nocase
        $str3 = "Restore-My-Files.txt" nocase
        $vss1 = "vssadmin Delete Shadows /All /Quiet" nocase
        $vss2 = "wmic shadowcopy delete" nocase
        $bcd1 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase
        $bcd2 = "bcdedit /set {default} recoveryenabled no" nocase
        $wb1 = "wbadmin delete catalog -quiet" nocase

    condition:
        ($str1 or $str2 or $str3) and (any of ($vss*) or any of ($bcd*) or $wb1) or
        (2 of ($vss*, $bcd*, $wb*))
}

rule WannaCry_Ransomware_Indicators {
    meta:
        description = "Detects WannaCry (WanaCrypt0r) ransomware components and killswitch artifacts"
        author = "USB Sentinel Threat Intelligence"
        family = "WannaCry"
        reference = "https://vx-underground.org"
        severity = "CRITICAL"
        threat_type = "Ransomware"

    strings:
        $wc1 = "WanaCrypt0r" nocase
        $wc2 = "@WanaDecryptor@" nocase
        $wc3 = "tasksche.exe" nocase
        $wc4 = "mssecsvc.exe" nocase
        $wc5 = "icacls . /grant Everyone:F" nocase
        $wc6 = "wnry" nocase

    condition:
        2 of ($wc*)
}

rule Stop_Djvu_Ransomware {
    meta:
        description = "Detects Stop/Djvu ransomware strings and typical ransom note patterns"
        author = "USB Sentinel Threat Intelligence"
        family = "Stop/Djvu"
        reference = "https://bazaar.abuse.ch/browse/tag/djvu/"
        severity = "HIGH"
        threat_type = "Ransomware"

    strings:
        $note1 = "_readme.txt" nocase
        $geo = "api.2ip.ua/geo.json" nocase
        $email1 = "helpteam@mail" nocase
        $email2 = "support@freshmail" nocase
        $email3 = "helpmanager@airmail" nocase
        $phrase1 = "All your files, like pictures, databases, documents and other important are encrypted" nocase
        $phrase2 = "Don't worry, you can return all your files!" nocase

    condition:
        ($note1 and ($geo or any of ($email*) or $phrase1 or $phrase2)) or
        ($phrase1 and $phrase2)
}

rule Generic_ShadowCopy_Wiper {
    meta:
        description = "Detects generic batch or script commands destroying Windows backup and shadow copies"
        author = "USB Sentinel Threat Intelligence"
        severity = "HIGH"
        threat_type = "Ransomware-Tactic"

    strings:
        $cmd1 = "vssadmin" nocase
        $cmd2 = "delete shadows" nocase
        $cmd3 = "wmic shadowcopy delete" nocase
        $cmd4 = "wbadmin delete systemstatebackup" nocase

    condition:
        ($cmd1 and $cmd2) or $cmd3 or $cmd4
}

