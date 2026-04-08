rule URLDownload_Dropper
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects file download and execute pattern"
        severity = 7
        date = "2026-04-03"

    strings:
        $dl1 = "URLDownloadToFile" ascii
        $dl2 = "URLDownloadToFileA" ascii
        $dl3 = "URLDownloadToFileW" ascii
        $exec1 = "ShellExecute" ascii
        $exec2 = "CreateProcess" ascii
        $exec3 = "WinExec" ascii
        $exec4 = "system" ascii
        $temp1 = "%TEMP%" ascii wide
        $temp2 = "\\Temp\\" ascii wide
        $temp3 = "GetTempPath" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            (1 of ($dl*) and 1 of ($exec*) and 1 of ($temp*)) or
            (1 of ($dl*) and 2 of ($exec*))
        )
}

rule PowerShell_Download_Cradle
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects PowerShell download cradle patterns"
        severity = 8
        date = "2026-04-03"

    strings:
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "pwsh" ascii wide
        $dl1 = "DownloadString" ascii wide
        $dl2 = "DownloadFile" ascii wide
        $dl3 = "Invoke-WebRequest" ascii wide nocase
        $dl4 = "wget" ascii wide
        $dl5 = "curl" ascii wide
        $dl6 = "Net.WebClient" ascii wide
        $exec1 = "Invoke-Expression" ascii wide nocase
        $exec2 = "IEX" ascii wide
        $enc1 = "-enc " ascii wide nocase
        $enc2 = "-EncodedCommand" ascii wide nocase
        $bypass = "-ExecutionPolicy Bypass" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (
            (1 of ($ps*) and 1 of ($dl*) and 1 of ($exec*)) or
            (1 of ($ps*) and 1 of ($enc*) and 1 of ($dl*)) or
            ($bypass and 1 of ($dl*))
        )
}

rule Certutil_Download_Abuse
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects certutil abuse for downloading files"
        severity = 7
        date = "2026-04-03"

    strings:
        $cert = "certutil" ascii wide nocase
        $dl1 = "-urlcache" ascii wide nocase
        $dl2 = "-split" ascii wide nocase
        $dl3 = "-f " ascii wide
        $dec1 = "-decode" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        $cert and
        (1 of ($dl*) or $dec1)
}

rule Embedded_PE_In_Resource
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects embedded PE files inside resources"
        severity = 6
        date = "2026-04-03"

    strings:
        $mz = { 4D 5A 90 00 03 00 00 00 }
        $pe_sig = "This program cannot be run in DOS mode" ascii

    condition:
        uint16(0) == 0x5A4D and
        (#mz > 1 or (#pe_sig > 1))
}
