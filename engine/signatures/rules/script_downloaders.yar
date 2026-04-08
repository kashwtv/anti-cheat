/*
    YARA Rules - Script Downloaders & Loaders
    Detects the "loadstring + HttpGet" pattern that loads remote scripts and
    multi-stage downloaders that pull payloads from external hosts.
*/

rule Script_Loadstring_HttpGet : script_downloader
{
    meta:
        author = "AntiCheat Engine"
        description = "Lua loadstring(HttpGet(...)) cheat-loader pattern"
        severity = 4
        is_cheat_related = "true"
        date = "2026-04-07"

    strings:
        $loadstring = "loadstring" ascii nocase
        $httpget = "HttpGet" ascii nocase
        $getasync = "GetAsync" ascii nocase
        $game_service = "game:GetService" ascii

    condition:
        $loadstring and ($httpget or $getasync or $game_service)
}

rule Script_Multistage_Downloader : script_downloader
{
    meta:
        author = "AntiCheat Engine"
        description = "Script that downloads and writes a binary payload"
        severity = 8
        date = "2026-04-07"

    strings:
        $http1 = "HttpGet"
        $http2 = "GetAsync"
        $http3 = "PostAsync"
        $http4 = "Invoke-WebRequest"
        $http5 = "fetch("
        $write1 = "writefile"
        $write2 = "WriteAllBytes"
        $write3 = "io.open"
        $exe1 = ".exe"
        $exe2 = ".dll"
        $exe3 = ".scr"
        $exe4 = ".bat"

    condition:
        any of ($http*) and any of ($write*) and any of ($exe*)
}

rule Script_Pastebin_Downloader : script_downloader
{
    meta:
        author = "AntiCheat Engine"
        description = "References pastebin/raw paste services as a download source"
        severity = 5
        date = "2026-04-07"

    strings:
        $p1 = "pastebin.com/raw/"
        $p2 = "paste.ee/p/"
        $p3 = "hastebin.com/raw/"
        $p4 = "ghostbin.co/paste/"
        $http = /HttpGet|GetAsync|fetch\(|Invoke-WebRequest/

    condition:
        any of ($p*) and $http
}

rule Script_Discord_CDN_Downloader : script_downloader
{
    meta:
        author = "AntiCheat Engine"
        description = "Downloads from Discord CDN attachments - frequently abused for malware"
        severity = 7
        date = "2026-04-07"

    strings:
        $cdn1 = "cdn.discordapp.com/attachments/"
        $cdn2 = "media.discordapp.net/attachments/"
        $http = /HttpGet|GetAsync|fetch\(|Invoke-WebRequest|writefile|WriteAllBytes/

    condition:
        any of ($cdn*) and $http
}

rule Script_Github_Raw_Downloader : script_downloader
{
    meta:
        author = "AntiCheat Engine"
        description = "Downloads from raw.githubusercontent.com - common cheat distribution"
        severity = 3
        is_cheat_related = "true"
        date = "2026-04-07"

    strings:
        $gh = "raw.githubusercontent.com"
        $loader1 = "loadstring"
        $loader2 = "HttpGet"
        $loader3 = "GetAsync"

    condition:
        $gh and any of ($loader*)
}

rule Script_Powershell_Downloader : script_downloader
{
    meta:
        author = "AntiCheat Engine"
        description = "PowerShell IEX download cradle"
        severity = 9
        date = "2026-04-07"

    strings:
        $iex1 = "Invoke-Expression" nocase
        $iex2 = "IEX" wide ascii
        $iwr = "Invoke-WebRequest" nocase
        $dl = "DownloadString" nocase
        $net = "Net.WebClient" nocase

    condition:
        ($iex1 or $iex2) and ($iwr or $dl or $net)
}
