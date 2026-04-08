rule Generic_Keylogger
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects keylogging behavior"
        severity = 8
        date = "2026-04-03"

    strings:
        $api1 = "GetAsyncKeyState" ascii
        $api2 = "SetWindowsHookExA" ascii
        $api3 = "SetWindowsHookExW" ascii
        $api4 = "GetKeyState" ascii
        $api5 = "GetKeyboardState" ascii
        $api6 = "MapVirtualKey" ascii
        $api7 = "RegisterRawInputDevices" ascii
        $log1 = "keylog" ascii wide nocase
        $log2 = "[ENTER]" ascii wide
        $log3 = "[BACKSPACE]" ascii wide
        $log4 = "[TAB]" ascii wide
        $log5 = "[SHIFT]" ascii wide
        $file1 = "\\keystrokes" ascii wide nocase
        $file2 = "\\keys.txt" ascii wide
        $file3 = "\\typed.txt" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($api*) and 2 of ($log*)) or
            (1 of ($api*) and 1 of ($log*) and 1 of ($file*)) or
            (3 of ($log*) and 1 of ($api*))
        )
}
