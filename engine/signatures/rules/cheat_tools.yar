/*
    YARA Rules - Known Cheat Tool Identification
    INFORMATIONAL ONLY - These are NOT malicious detections.
    These rules identify common cheat tools to help with classification.
*/

rule Game_Injector : cheat_tool
{
    meta:
        author = "AntiCheat Engine"
        description = "Generic game DLL injector"
        severity = 1
        date = "2026-04-03"
        info = "INFORMATIONAL - Not malicious"

    strings:
        $api1 = "CreateRemoteThread" ascii
        $api2 = "VirtualAllocEx" ascii
        $api3 = "WriteProcessMemory" ascii
        $api4 = "LoadLibraryA" ascii
        $api5 = "OpenProcess" ascii
        $ui1 = "inject" ascii wide nocase
        $ui2 = "DLL" ascii wide
        $ui3 = "process" ascii wide nocase
        $ui4 = "select" ascii wide nocase
        $game1 = ".exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (3 of ($api*) and 2 of ($ui*))
}

rule Memory_Editor_CheatEngine_Like : cheat_tool
{
    meta:
        author = "AntiCheat Engine"
        description = "Memory editor similar to Cheat Engine"
        severity = 1
        date = "2026-04-03"
        info = "INFORMATIONAL - Not malicious"

    strings:
        $api1 = "ReadProcessMemory" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "VirtualQueryEx" ascii
        $api4 = "OpenProcess" ascii
        $ui1 = "scan" ascii wide nocase
        $ui2 = "value" ascii wide nocase
        $ui3 = "address" ascii wide nocase
        $ui4 = "memory" ascii wide nocase
        $ui5 = "freeze" ascii wide nocase
        $type1 = "4 Bytes" ascii wide
        $type2 = "Float" ascii wide
        $type3 = "Double" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            (3 of ($api*) and 2 of ($ui*)) or
            (2 of ($api*) and 2 of ($type*))
        )
}

rule Game_Trainer : cheat_tool
{
    meta:
        author = "AntiCheat Engine"
        description = "Game trainer application"
        severity = 1
        date = "2026-04-03"
        info = "INFORMATIONAL - Not malicious"

    strings:
        $s1 = "trainer" ascii wide nocase
        $s2 = "Num1" ascii wide
        $s3 = "Num2" ascii wide
        $s4 = "Num3" ascii wide
        $s5 = "Hotkey" ascii wide nocase
        $feat1 = "Infinite Health" ascii wide nocase
        $feat2 = "Infinite Ammo" ascii wide nocase
        $feat3 = "God Mode" ascii wide nocase
        $feat4 = "No Recoil" ascii wide nocase
        $feat5 = "Super Speed" ascii wide nocase
        $api1 = "WriteProcessMemory" ascii
        $api2 = "ReadProcessMemory" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            ($s1 and 2 of ($s2, $s3, $s4, $s5)) or
            (2 of ($feat*)) or
            (1 of ($api*) and $s1 and 1 of ($s*))
        )
}

rule ESP_Wallhack : cheat_tool
{
    meta:
        author = "AntiCheat Engine"
        description = "ESP/Wallhack cheat overlay"
        severity = 1
        date = "2026-04-03"
        info = "INFORMATIONAL - Not malicious"

    strings:
        $s1 = "ESP" ascii wide
        $s2 = "wallhack" ascii wide nocase
        $s3 = "aimbot" ascii wide nocase
        $s4 = "triggerbot" ascii wide nocase
        $draw1 = "DrawLine" ascii wide
        $draw2 = "DrawBox" ascii wide
        $draw3 = "DrawText" ascii wide
        $draw4 = "overlay" ascii wide nocase
        $gdi1 = "Direct3D" ascii wide
        $gdi2 = "DirectX" ascii wide
        $gdi3 = "D3D11" ascii wide
        $gdi4 = "OpenGL" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($s*) and 1 of ($draw*)) or
            (1 of ($s*) and 1 of ($draw*) and 1 of ($gdi*)) or
            (2 of ($s*) and 1 of ($gdi*))
        )
}
