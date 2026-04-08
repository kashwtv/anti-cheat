/*
    YARA Rules - Discord Webhook Exfiltration Patterns
    Detects scripts and tools that exfiltrate stolen data via Discord webhooks.
    Common in the Roblox/gaming cheat ecosystem where attackers use free
    Discord infrastructure as a C2/exfil channel.
*/

rule Discord_Webhook_Data_Exfil
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects scripts that POST stolen data to Discord webhooks using embedded fields"
        severity = 9
        date = "2026-04-04"
        reference = "internal"

    strings:
        // Discord webhook URLs
        $webhook1 = "discord.com/api/webhooks/" ascii wide
        $webhook2 = "discordapp.com/api/webhooks/" ascii wide
        $webhook3 = /https?:\/\/(discord|discordapp)\.com\/api\/webhooks\/\d{17,20}\/[\w-]+/ ascii

        // HTTP POST methods
        $post1 = "POST" ascii wide
        $post2 = "request(" ascii
        $post3 = "HttpPost" ascii nocase
        $post4 = "syn.request" ascii nocase
        $post5 = "http_request" ascii nocase
        $post6 = "fetch(" ascii
        $post7 = "requests.post" ascii
        $post8 = "httpservice" ascii nocase

        // Embed structure with stolen data fields
        $embed1 = "embeds" ascii wide
        $embed2 = "fields" ascii wide
        $embed3 = "content" ascii wide

        // Stolen data keywords in embed fields
        $stolen1 = "token" ascii wide nocase
        $stolen2 = "password" ascii wide nocase
        $stolen3 = "cookie" ascii wide nocase
        $stolen4 = "credentials" ascii wide nocase
        $stolen5 = "ip" ascii wide nocase
        $stolen6 = "hwid" ascii wide nocase
        $stolen7 = "roblosecurity" ascii wide nocase
        $stolen8 = "credit card" ascii wide nocase
        $stolen9 = "ssn" ascii wide nocase
        $stolen10 = "seed phrase" ascii wide nocase
        $stolen11 = "private key" ascii wide nocase

    condition:
        1 of ($webhook*) and
        1 of ($post*) and
        (
            (1 of ($embed*) and 2 of ($stolen*)) or
            (3 of ($stolen*))
        )
}

rule Discord_Token_Grabber_Script
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects scripts combining Discord local storage access, webhook exfil, and token references"
        severity = 10
        date = "2026-04-04"
        reference = "internal"

    strings:
        // Discord local storage paths
        $path1 = "\\discord\\Local Storage\\leveldb" ascii wide nocase
        $path2 = "\\discordcanary\\Local Storage\\leveldb" ascii wide nocase
        $path3 = "\\discordptb\\Local Storage\\leveldb" ascii wide nocase
        $path4 = "Local Storage" ascii wide nocase
        $path5 = "leveldb" ascii wide nocase
        $path6 = "discord" ascii wide nocase

        // Webhook exfiltration
        $webhook1 = "discord.com/api/webhooks" ascii wide
        $webhook2 = "discordapp.com/api/webhooks" ascii wide
        $webhook3 = /https?:\/\/(discord|discordapp)\.com\/api\/webhooks\/\d{17,20}/ ascii

        // Token references
        $token1 = "token" ascii wide nocase
        $token2 = /[\"\'][\w-]{24}\.[\w-]{6}\.[\w-]{27}[\"\']/ ascii
        $token3 = /mfa\.[\w-]{84}/ ascii
        $token4 = "getToken" ascii nocase
        $token5 = "grabToken" ascii nocase
        $token6 = "tokenGrabber" ascii nocase

        // File reading patterns (for reading LevelDB)
        $read1 = "readfile(" ascii nocase
        $read2 = "io.open(" ascii
        $read3 = "listfiles(" ascii nocase
        $read4 = "isfile(" ascii nocase
        $read5 = "os.getenv" ascii

    condition:
        (
            (2 of ($path*) and 1 of ($webhook*) and 1 of ($token*)) or
            (1 of ($path*) and 1 of ($webhook*) and 2 of ($token*) and 1 of ($read*)) or
            (2 of ($path*) and 1 of ($token*) and 1 of ($read*) and 1 of ($webhook*))
        )
}

rule Discord_Nitro_Scam
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects fake Nitro generators that are actually token stealers"
        severity = 8
        date = "2026-04-04"
        reference = "internal"

    strings:
        // Nitro bait strings
        $nitro1 = "nitro" ascii wide nocase
        $nitro2 = "gift" ascii wide nocase
        $nitro3 = "discord.gift/" ascii wide nocase
        $nitro4 = "nitro generator" ascii wide nocase
        $nitro5 = "free nitro" ascii wide nocase
        $nitro6 = "nitro gen" ascii wide nocase
        $nitro7 = "discord.com/gifts/" ascii wide

        // Actual malicious behavior behind the bait
        $steal1 = "token" ascii wide nocase
        $steal2 = "password" ascii wide nocase
        $steal3 = "Local Storage" ascii wide nocase
        $steal4 = "leveldb" ascii wide nocase
        $steal5 = "grabToken" ascii wide nocase
        $steal6 = ".ROBLOSECURITY" ascii wide

        // Exfiltration
        $exfil1 = "webhook" ascii wide nocase
        $exfil2 = "discord.com/api/webhooks" ascii wide
        $exfil3 = "discordapp.com/api/webhooks" ascii wide
        $exfil4 = "request(" ascii
        $exfil5 = "HttpPost" ascii nocase

        // Generation facade
        $gen1 = "generating" ascii wide nocase
        $gen2 = "checking" ascii wide nocase
        $gen3 = "valid" ascii wide nocase
        $gen4 = "invalid" ascii wide nocase

    condition:
        2 of ($nitro*) and
        (
            (2 of ($steal*) and 1 of ($exfil*)) or
            (1 of ($steal*) and 1 of ($exfil*) and 2 of ($gen*)) or
            (2 of ($steal*) and 2 of ($gen*))
        )
}
