/*
  USB Sentinel - YARA Rules: Living-Off-The-Land Binaries (LOLBins) & Script Evasion
  Covers encoded PowerShell, Certutil/Bitsadmin downloaders, MSHTA, and malicious Office macros.
*/

rule Suspicious_Encoded_PowerShell {
    meta:
        description = "Detects base64-encoded or obfuscated PowerShell invocation used in USB stagers"
        author = "USB Sentinel Threat Intelligence"
        severity = "HIGH"
        threat_type = "Defense-Evasion"

    strings:
        $ps1 = "powershell" nocase
        $ps2 = "pwsh" nocase
        $enc1 = "-enc " nocase
        $enc2 = "-encodedcommand " nocase
        $enc3 = "FromBase64String" nocase
        $enc4 = "[System.Text.Encoding]::" nocase
        $bypass1 = "-executionpolicy bypass" nocase
        $bypass2 = "-ep bypass" nocase
        $hidden = "-w hidden" nocase
        $iex = "IEX(" nocase
        $invoke = "Invoke-Expression" nocase

    condition:
        ($ps1 or $ps2) and (($enc1 or $enc2 or $enc3 or $enc4) or ($hidden and ($bypass1 or $bypass2 or $iex or $invoke)))
}

rule Certutil_Bitsadmin_Downloader {
    meta:
        description = "Detects CertUtil or BitsAdmin abuse for dropping payloads from remote servers"
        author = "USB Sentinel Threat Intelligence"
        severity = "HIGH"
        threat_type = "Downloader"

    strings:
        $cu1 = "certutil" nocase
        $cu2 = "-urlcache" nocase
        $cu3 = "-split" nocase
        $ba1 = "bitsadmin" nocase
        $ba2 = "/transfer" nocase
        $url1 = "http://" nocase
        $url2 = "https://" nocase

    condition:
        ($cu1 and $cu2 and $cu3 and ($url1 or $url2)) or
        ($ba1 and $ba2 and ($url1 or $url2))
}

rule MSHTA_Script_Execution {
    meta:
        description = "Detects MSHTA abuse executing inline VBScript/JavaScript or remote HTA"
        author = "USB Sentinel Threat Intelligence"
        severity = "HIGH"
        threat_type = "Execution"

    strings:
        $mshta = "mshta.exe" nocase
        $vbs = "vbscript:Execute" nocase
        $js = "javascript:" nocase
        $hta = ".hta" nocase
        $http = "http://" nocase
        $https = "https://" nocase

    condition:
        $mshta and ($vbs or $js or ($hta and ($http or $https)))
}

rule Office_Malicious_AutoExec_Macro {
    meta:
        description = "Detects suspicious Office Macro AutoExec hooks combined with process launch"
        author = "USB Sentinel Threat Intelligence"
        severity = "HIGH"
        threat_type = "Macro-Dropper"

    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Workbook_Open" nocase
        $auto3 = "Document_Open" nocase
        $auto4 = "AutoExec" nocase
        $exec1 = "WScript.Shell" nocase
        $exec2 = "ShellExecute" nocase
        $exec3 = "CreateObject(\"Scripting.FileSystemObject\")" nocase
        $exec4 = "Environ(\"APPDATA\")" nocase
        $exec5 = "powershell" nocase

    condition:
        any of ($auto*) and any of ($exec*)
}

