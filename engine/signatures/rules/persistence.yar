rule Registry_Run_Key_Persistence
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects registry Run key persistence mechanism"
        severity = 6
        date = "2026-04-03"

    strings:
        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $reg2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide
        $reg3 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii wide
        $api1 = "RegSetValueEx" ascii
        $api2 = "RegCreateKeyEx" ascii
        $api3 = "RegOpenKeyEx" ascii

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($reg*) and 1 of ($api*))
}

rule Scheduled_Task_Persistence
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects scheduled task creation for persistence"
        severity = 7
        date = "2026-04-03"

    strings:
        $schtasks = "schtasks" ascii wide nocase
        $create = "/create" ascii wide nocase
        $xml1 = "ITaskService" ascii wide
        $xml2 = "ITaskFolder" ascii wide
        $xml3 = "RegisterTaskDefinition" ascii wide
        $trigger1 = "/sc onlogon" ascii wide nocase
        $trigger2 = "/sc onstart" ascii wide nocase
        $trigger3 = "TASK_TRIGGER_LOGON" ascii wide
        $trigger4 = "TASK_TRIGGER_BOOT" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            ($schtasks and $create and 1 of ($trigger*)) or
            (2 of ($xml*) and 1 of ($trigger*))
        )
}

rule Service_Install_Persistence
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects Windows service installation for persistence"
        severity = 7
        date = "2026-04-03"

    strings:
        $api1 = "CreateServiceA" ascii
        $api2 = "CreateServiceW" ascii
        $api3 = "OpenSCManager" ascii
        $api4 = "StartService" ascii
        $api5 = "ChangeServiceConfig" ascii
        $sc1 = "sc create" ascii wide nocase
        $sc2 = "sc config" ascii wide nocase
        $auto = "SERVICE_AUTO_START" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            ($api3 and 1 of ($api1, $api2)) or
            (1 of ($sc*) and $auto) or
            ($api3 and $api4 and $auto)
        )
}

rule Startup_Folder_Persistence
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects startup folder usage for persistence"
        severity = 5
        date = "2026-04-03"

    strings:
        $path1 = "\\Start Menu\\Programs\\Startup" ascii wide
        $path2 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii wide
        $api1 = "SHGetFolderPath" ascii
        $api2 = "SHGetKnownFolderPath" ascii
        $copy1 = "CopyFile" ascii
        $copy2 = "File.Copy" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            (1 of ($path*) and 1 of ($copy*)) or
            (1 of ($api*) and 1 of ($path*))
        )
}
