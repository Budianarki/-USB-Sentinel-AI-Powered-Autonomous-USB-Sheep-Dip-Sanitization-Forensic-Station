/*
  USB Sentinel - YARA Rules: InfoStealers & Spyware
  Targets RedLine, Lumma, AgentTesla, Vidar, and credential dumping utilities.
*/

rule RedLine_Stealer_Signatures {
    meta:
        description = "Detects RedLine Stealer targeting Chromium cookies, crypto wallets, and system tokens"
        author = "USB Sentinel Threat Intelligence"
        family = "RedLine"
        reference = "https://bazaar.abuse.ch/browse/tag/RedLineStealer/"
        severity = "CRITICAL"
        threat_type = "Infostealer"

    strings:
        $str1 = "RedLineStealer" nocase
        $str2 = "encryptedUsername" nocase
        $str3 = "encryptedPassword" nocase
        $str4 = "moz_logins" nocase
        $str5 = "SELECT host_key, name, path, encrypted_value FROM cookies" nocase
        $str6 = "wallet.dat" nocase
        $str7 = "CardNumber" nocase
        $str8 = "ExpirationMonth" nocase

    condition:
        ($str1) or
        (3 of ($str2, $str3, $str4, $str5, $str6, $str7, $str8))
}

rule AgentTesla_Spyware_Artifacts {
    meta:
        description = "Detects AgentTesla keylogger and credential exfiltration payload strings"
        author = "USB Sentinel Threat Intelligence"
        family = "AgentTesla"
        reference = "https://bazaar.abuse.ch/browse/tag/AgentTesla/"
        severity = "HIGH"
        threat_type = "Spyware/Keylogger"

    strings:
        $at1 = "AgentTesla" nocase
        $at2 = "GetClipboardText" nocase
        $at3 = "smtp.mail" nocase
        $at4 = "ftp://" nocase
        $at5 = "SmtpClient" nocase
        $at6 = "EnableSsl" nocase
        $at7 = "IAsyncResult" nocase
        $at8 = "webcam" nocase

    condition:
        ($at1) or
        ($at2 and ($at3 or $at5) and any of ($at4, $at6, $at7, $at8))
}

rule Lumma_Stealer_Indicators {
    meta:
        description = "Detects Lumma Stealer targeting Telegram, Discord, and crypto extension data"
        author = "USB Sentinel Threat Intelligence"
        family = "Lumma"
        reference = "https://bazaar.abuse.ch/browse/tag/LummaStealer/"
        severity = "CRITICAL"
        threat_type = "Infostealer"

    strings:
        $lm1 = "lummastealer" nocase
        $lm2 = "LummaC" nocase
        $tdata = "Telegram Desktop\\tdata" nocase
        $discord = "Discord\\Local Storage" nocase
        $metamask = "nkbihfbeogaeaoehlefnkodbefgpgknn" nocase
        $phantom = "bfnaelmomeimhlpmgjnjophhpkkoljpa" nocase

    condition:
        ($lm1 or $lm2) or
        (2 of ($tdata, $discord, $metamask, $phantom))
}

