/*
    YARA Rules for Suspicious PowerShell Activity
    Author: Zviar
    Description: Detects common malicious PowerShell patterns
*/

rule Suspicious_PowerShell_EncodedCommand {
    meta:
        description = "Detects PowerShell scripts with encoded commands"
        author = "Zviar"
        date = "2025-01-06"
        severity = "medium"
        
    strings:
        $enc1 = "-enc" nocase
        $enc2 = "-encodedcommand" nocase
        $enc3 = "-e " nocase
        $b64 = /[A-Za-z0-9+\/]{50,}={0,2}/ // Base64 pattern
        
    condition:
        any of ($enc*) and $b64
}

rule Suspicious_PowerShell_DownloadExecute {
    meta:
        description = "Detects PowerShell download and execute patterns"
        author = "Zviar"
        date = "2025-01-06"
        severity = "high"
        
    strings:
        $download1 = "Net.WebClient" nocase
        $download2 = "DownloadString" nocase
        $download3 = "DownloadFile" nocase
        $download4 = "Invoke-WebRequest" nocase
        $download5 = "wget" nocase
        $download6 = "curl" nocase
        
        $exec1 = "IEX" nocase
        $exec2 = "Invoke-Expression" nocase
        $exec3 = "Invoke-Command" nocase
        
    condition:
        any of ($download*) and any of ($exec*)
}

rule Suspicious_PowerShell_ProcessInjection {
    meta:
        description = "Detects PowerShell process injection techniques"
        author = "Zviar"
        date = "2025-01-06"
        severity = "critical"
        reference = "MITRE ATT&CK T1055"
        
    strings:
        $api1 = "VirtualAlloc" nocase
        $api2 = "WriteProcessMemory" nocase
        $api3 = "CreateRemoteThread" nocase
        $api4 = "OpenProcess" nocase
        $api5 = "VirtualAllocEx" nocase
        
        $ps = "powershell" nocase
        
    condition:
        $ps and 2 of ($api*)
}

rule Suspicious_PowerShell_CredentialDumping {
    meta:
        description = "Detects PowerShell credential dumping tools"
        author = "Zviar"
        date = "2025-01-06"
        severity = "critical"
        reference = "MITRE ATT&CK T1003"
        
    strings:
        $mimikatz1 = "mimikatz" nocase
        $mimikatz2 = "sekurlsa" nocase
        $mimikatz3 = "logonpasswords" nocase
        
        $dump1 = "DumpCreds" nocase
        $dump2 = "Get-ProcessTokenPrivilege" nocase
        $dump3 = "Invoke-Mimikatz" nocase
        
        $lsass = "lsass" nocase
        
    condition:
        any of them
}

rule Suspicious_PowerShell_ObfuscatedScript {
    meta:
        description = "Detects heavily obfuscated PowerShell scripts"
        author = "Zviar"
        date = "2025-01-06"
        severity = "medium"
        
    strings:
        $obf1 = /\$\{[^}]{1,3}\}/ // Variable obfuscation ${a}
        $obf2 = /`[a-z]/i // Backtick obfuscation
        $obf3 = /-join/ nocase
        $obf4 = "[char]" nocase
        $obf5 = "iex" nocase
        
        $replace1 = "-replace" nocase
        $replace2 = ".replace(" nocase
        
    condition:
        3 of ($obf*) or (any of ($replace*) and any of ($obf*))
}

rule Suspicious_PowerShell_Persistence {
    meta:
        description = "Detects PowerShell persistence mechanisms"
        author = "Zviar"
        date = "2025-01-06"
        severity = "high"
        reference = "MITRE ATT&CK T1547"
        
    strings:
        $reg1 = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg3 = "CurrentVersion\\Run" nocase
        
        $schtasks = "schtasks" nocase
        $startup = "Startup" nocase
        
        $new_item = "New-Item" nocase
        $set_item = "Set-ItemProperty" nocase
        
    condition:
        (any of ($reg*) and any of ($new_item, $set_item)) or ($schtasks and $startup)
}
