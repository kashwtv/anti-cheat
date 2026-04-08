/*
    YARA Rules - Remote Access Trojans (RATs)
    Targets RATs commonly bundled with game cheats
*/

rule AsyncRAT
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects AsyncRAT remote access trojan"
        severity = 9
        date = "2026-04-03"
        reference = "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"

    strings:
        $mutex1 = "AsyncMutex_6SI8OkPnk" ascii wide
        $mutex2 = "AsyncMutex" ascii wide

        $class1 = "AsyncClient" ascii
        $class2 = "AsyncRAT" ascii
        $class3 = "Clients.Helper" ascii
        $class4 = "Packet.DoProcess" ascii

        $c2_1 = "get_Port" ascii
        $c2_2 = "get_Hosts" ascii
        $c2_3 = "get_Install" ascii
        $c2_4 = "get_MTX" ascii

        $net1 = "System.Net.Sockets.TcpClient" ascii
        $net2 = "SslStream" ascii

        $func1 = "SendToServer" ascii
        $func2 = "InitializeClient" ascii
        $func3 = "ClientSocket" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            (1 of ($mutex*) and 2 of ($class*)) or
            (3 of ($c2*) and 2 of ($class*)) or
            (2 of ($func*) and 1 of ($mutex*))
        )
}

rule QuasarRAT
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects QuasarRAT / xRAT remote access trojan"
        severity = 9
        date = "2026-04-03"
        reference = "https://github.com/quasar/Quasar"

    strings:
        $s1 = "Quasar.Client" ascii
        $s2 = "Quasar.Common" ascii
        $s3 = "QuasarRAT" ascii wide
        $s4 = "xRAT" ascii wide

        $class1 = "Client.Networking.QuasarClient" ascii
        $class2 = "Client.Commands.CommandHandler" ascii
        $class3 = "Client.Recovery.Browsers" ascii
        $class4 = "Client.Recovery.FtpClients" ascii

        $cmd1 = "DoShellExecute" ascii
        $cmd2 = "DoDownloadAndExecute" ascii
        $cmd3 = "DoUploadAndExecute" ascii
        $cmd4 = "DoVisitWebsite" ascii
        $cmd5 = "DoShowMessageBox" ascii
        $cmd6 = "GetPasswords" ascii
        $cmd7 = "GetDesktop" ascii

        $cfg1 = "ENCRYPTIONKEY" ascii
        $cfg2 = "LOGDIRECTORYNAME" ascii
        $cfg3 = "INSTALLSUB" ascii
        $cfg4 = "STARTUPKEY" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            (1 of ($s*) and 3 of ($cmd*)) or
            (2 of ($class*) and 2 of ($cfg*)) or
            (1 of ($s*) and 2 of ($cfg*) and 2 of ($cmd*))
        )
}

rule njRAT
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects njRAT / Bladabindi remote access trojan"
        severity = 9
        date = "2026-04-03"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.njrat"

    strings:
        $s1 = "njRAT" ascii wide nocase
        $s2 = "njq8" ascii wide
        $s3 = "Bladabindi" ascii wide
        $s4 = "HacKed" ascii wide

        $cmd1 = "kl" ascii wide fullword
        $cmd2 = "prof" ascii wide fullword
        $cmd3 = "rss" ascii wide fullword
        $cmd4 = "inv" ascii wide fullword
        $cmd5 = "ret" ascii wide fullword
        $cmd6 = "CAP" ascii wide fullword
        $cmd7 = "un" ascii wide fullword
        $cmd8 = "up" ascii wide fullword

        $net1 = "|'|'|" ascii wide
        $net2 = "netsh firewall add allowedprogram" ascii wide
        $net3 = "SEE_MASK_NOZONECHECKS" ascii wide

        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $reg2 = "\\njq8" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            (1 of ($s*) and 3 of ($cmd*)) or
            (1 of ($net*) and 4 of ($cmd*)) or
            (1 of ($s*) and 1 of ($net*) and 1 of ($reg*))
        )
}

rule DarkComet
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects DarkComet RAT"
        severity = 9
        date = "2026-04-03"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkcomet"

    strings:
        $s1 = "DarkComet" ascii wide nocase
        $s2 = "DC_MUTEX-" ascii wide
        $s3 = "DCPERSFWB" ascii wide
        $s4 = "#BOT#OpenUrl" ascii wide
        $s5 = "#BOT#KeyLogger" ascii wide

        $func1 = "GetSIN" ascii
        $func2 = "EditSIN" ascii
        $func3 = "ABORTSOCKETTHREAD" ascii
        $func4 = "ABORTKEYLOGGER" ascii

        $cfg1 = "GENCODE" ascii
        $cfg2 = "FAKEMSG" ascii
        $cfg3 = "SID=" ascii
        $cfg4 = "FWB=" ascii
        $cfg5 = "PERESSION=" ascii

        $keylog = "#KSLOG#" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($s*)) or
            (1 of ($s*) and 2 of ($func*)) or
            (3 of ($cfg*) and 1 of ($func*)) or
            ($keylog and 1 of ($s*))
        )
}

rule Generic_RAT_Indicators
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects generic RAT behavior patterns common in cheat-bundled malware"
        severity = 7
        date = "2026-04-03"
        reference = "internal"

    strings:
        $shell1 = "cmd.exe /c" ascii wide nocase
        $shell2 = "/bin/sh" ascii
        $shell3 = "powershell.exe -e" ascii wide nocase
        $shell4 = "CreatePipe" ascii
        $shell5 = "ConnectNamedPipe" ascii

        $revshell1 = "WSASocketA" ascii
        $revshell2 = "WSAStartup" ascii
        $revshell3 = "connect" ascii
        $revshell4 = "cmd.exe" ascii wide
        $revshell5 = "CreateProcessA" ascii

        $rdp1 = "RemoteDesktop" ascii wide
        $rdp2 = "ScreenCapture" ascii wide
        $rdp3 = "GetDesktopWindow" ascii
        $rdp4 = "BitBlt" ascii
        $rdp5 = "CaptureMouse" ascii wide

        $cam1 = "WebcamStart" ascii wide
        $cam2 = "avicap32" ascii
        $cam3 = "capCreateCaptureWindow" ascii

        $file1 = "FileManager" ascii wide
        $file2 = "UploadFile" ascii wide
        $file3 = "DownloadFile" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (2 of ($shell*) and 2 of ($revshell*) and 1 of ($rdp*)) or
            (3 of ($rdp*) and 1 of ($cam*) and 1 of ($file*)) or
            (2 of ($shell*) and 1 of ($cam*) and 2 of ($file*))
        )
}
