rule Discord_Webhook_C2
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects Discord webhook abuse for C2 or data exfiltration"
        severity = 8
        date = "2026-04-03"

    strings:
        $webhook1 = "discord.com/api/webhooks/" ascii wide
        $webhook2 = "discordapp.com/api/webhooks/" ascii wide
        $send1 = "POST" ascii wide
        $send2 = "HttpSendRequest" ascii
        $send3 = "WebClient" ascii wide
        $content = "content" ascii wide
        $embed = "embeds" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            (1 of ($webhook*) and 1 of ($send*)) or
            (1 of ($webhook*) and ($content or $embed))
        )
}

rule Pastebin_C2
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects Pastebin abuse for C2 configuration retrieval"
        severity = 7
        date = "2026-04-03"

    strings:
        $pb1 = "pastebin.com/raw/" ascii wide
        $pb2 = "hastebin.com/raw/" ascii wide
        $pb3 = "paste.ee/r/" ascii wide
        $pb4 = "rentry.co/raw/" ascii wide
        $dl1 = "DownloadString" ascii wide
        $dl2 = "HttpWebRequest" ascii wide
        $dl3 = "WebClient" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($pb*) and 1 of ($dl*))
}

rule Cobalt_Strike_Beacon
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects Cobalt Strike beacon indicators"
        severity = 10
        date = "2026-04-03"

    strings:
        $s1 = "%s.4444" ascii
        $s2 = "beacon.dll" ascii wide
        $s3 = "beacon.x64.dll" ascii wide
        $s4 = "ReflectiveLoader" ascii
        $pipe1 = "\\\\.\\pipe\\msagent_" ascii
        $pipe2 = "\\\\.\\pipe\\MSSE-" ascii
        $config = { 00 01 00 01 00 02 }

    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($s*)) or
            (1 of ($pipe*) and 1 of ($s*)) or
            ($s4 and $config)
        )
}

rule Generic_C2_Communication
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects generic C2 communication patterns"
        severity = 7
        date = "2026-04-03"

    strings:
        $sleep1 = "Sleep" ascii
        $sleep2 = "Thread.Sleep" ascii wide
        $http1 = "HttpWebRequest" ascii wide
        $http2 = "WebClient" ascii wide
        $http3 = "HttpClient" ascii wide
        $ua1 = "Mozilla/5.0" ascii wide
        $ua2 = "User-Agent" ascii wide
        $b64_1 = "Convert.FromBase64String" ascii wide
        $b64_2 = "Convert.ToBase64String" ascii wide
        $cmd1 = "cmd.exe /c" ascii wide
        $cmd2 = "powershell" ascii wide nocase
        $whoami = "whoami" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (1 of ($http*) and 1 of ($b64*) and 1 of ($cmd*)) or
            (1 of ($sleep*) and 1 of ($http*) and $whoami and 1 of ($cmd*)) or
            (1 of ($http*) and 1 of ($ua*) and 1 of ($b64*) and 1 of ($cmd*))
        )
}
