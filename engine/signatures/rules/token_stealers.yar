/*
    YARA Rules - Browser Token/Cookie Stealer Patterns (Script-Focused)
    Targets scripts (rather than compiled binaries) that steal browser
    credentials, Roblox cookies, and multi-platform session tokens.
*/

rule Browser_Token_Stealer_Script
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects script-based access to browser credential stores (Chrome, Firefox, Edge, Brave)"
        severity = 9
        date = "2026-04-04"
        reference = "internal"

    strings:
        // Chrome credential paths
        $chrome1 = "Google\\Chrome\\User Data" ascii wide nocase
        $chrome2 = "Default\\Login Data" ascii wide nocase
        $chrome3 = "Default\\Cookies" ascii wide nocase
        $chrome4 = "Default\\Web Data" ascii wide nocase
        $chrome5 = "Local State" ascii wide nocase
        $chrome6 = "encrypted_key" ascii wide nocase

        // Firefox credential paths
        $ff1 = "Mozilla\\Firefox\\Profiles" ascii wide nocase
        $ff2 = "logins.json" ascii wide nocase
        $ff3 = "cookies.sqlite" ascii wide nocase
        $ff4 = "key4.db" ascii wide nocase

        // Edge credential paths
        $edge1 = "Microsoft\\Edge\\User Data" ascii wide nocase

        // Brave credential paths
        $brave1 = "BraveSoftware\\Brave-Browser\\User Data" ascii wide nocase

        // Opera credential paths
        $opera1 = "Opera Software\\Opera Stable" ascii wide nocase

        // Script-level file operations (not Win32 API)
        $read1 = "readfile(" ascii nocase
        $read2 = "io.open(" ascii
        $read3 = "open(" ascii
        $read4 = "os.getenv" ascii
        $read5 = "APPDATA" ascii wide
        $read6 = "LOCALAPPDATA" ascii wide

        // Decryption or parsing keywords
        $decrypt1 = "decrypt" ascii wide nocase
        $decrypt2 = "aes" ascii wide nocase
        $decrypt3 = "base64" ascii wide nocase
        $decrypt4 = "CryptUnprotectData" ascii wide
        $decrypt5 = "dpapi" ascii wide nocase
        $decrypt6 = "master_key" ascii wide nocase

        // Exfiltration
        $exfil1 = "webhook" ascii wide nocase
        $exfil2 = "request(" ascii
        $exfil3 = "HttpPost" ascii nocase
        $exfil4 = "POST" ascii wide
        $exfil5 = "send(" ascii

    condition:
        (
            (2 of ($chrome*) and 1 of ($read*) and 1 of ($exfil*)) or
            (1 of ($chrome*) and 1 of ($ff*) and 1 of ($read*)) or
            (1 of ($chrome*) and 1 of ($decrypt*) and 1 of ($exfil*)) or
            (1 of ($ff*) and 1 of ($decrypt*) and 1 of ($exfil*)) or
            (1 of ($edge1, $brave1, $opera1) and 1 of ($chrome*) and 1 of ($read*) and 1 of ($exfil*))
        )
}

rule Roblox_Cookie_Stealer
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects scripts specifically targeting .ROBLOSECURITY cookie theft"
        severity = 10
        date = "2026-04-04"
        reference = "internal"

    strings:
        // Roblox security cookie identifiers
        $cookie1 = ".ROBLOSECURITY" ascii wide
        $cookie2 = "ROBLOSECURITY" ascii wide
        $cookie3 = "_|WARNING:-DO-NOT-SHARE-THIS" ascii wide

        // Roblox cookie storage locations
        $store1 = "HKCU\\Software\\Roblox\\RobloxStudioBrowser" ascii wide nocase
        $store2 = "RobloxStudioBrowser" ascii wide nocase
        $store3 = "Roblox\\GlobalBasicSettings" ascii wide nocase
        $store4 = "roblox.com" ascii wide nocase
        $store5 = "\\Roblox\\Cookies" ascii wide nocase

        // Cookie extraction methods
        $method1 = "readfile(" ascii nocase
        $method2 = "io.open(" ascii
        $method3 = "os.getenv" ascii
        $method4 = "getenv" ascii nocase
        $method5 = "RegGetValue" ascii nocase
        $method6 = "reg query" ascii nocase

        // Exfiltration of cookie
        $exfil1 = "webhook" ascii wide nocase
        $exfil2 = "discord.com/api/webhooks" ascii wide
        $exfil3 = "HttpPost" ascii nocase
        $exfil4 = "request(" ascii
        $exfil5 = "syn.request" ascii nocase
        $exfil6 = "http_request" ascii nocase
        $exfil7 = "httpservice" ascii nocase

        // Roblox API validation of stolen cookie
        $validate1 = "roblox.com/mobileapi/userinfo" ascii wide nocase
        $validate2 = "users.roblox.com/v1/users/authenticated" ascii wide nocase
        $validate3 = "auth.roblox.com" ascii wide nocase

    condition:
        (
            (1 of ($cookie*) and 1 of ($exfil*)) or
            (1 of ($cookie*) and 1 of ($method*) and 1 of ($validate*)) or
            (1 of ($store*) and 1 of ($cookie*) and 1 of ($method*)) or
            ($cookie3 and 1 of ($exfil*))
        )
}

rule Multi_Platform_Stealer_Script
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects scripts targeting multiple platforms simultaneously (Discord + Steam + Roblox)"
        severity = 10
        date = "2026-04-04"
        reference = "internal"

    strings:
        // Discord targets
        $discord1 = "discord" ascii wide nocase
        $discord2 = "Local Storage\\leveldb" ascii wide nocase
        $discord3 = "discordcanary" ascii wide nocase
        $discord4 = "token" ascii wide nocase

        // Steam targets
        $steam1 = "\\Steam\\config" ascii wide nocase
        $steam2 = "loginusers.vdf" ascii wide nocase
        $steam3 = "ssfn" ascii wide nocase
        $steam4 = "SteamAppData.vdf" ascii wide nocase
        $steam5 = "Software\\Valve\\Steam" ascii wide nocase

        // Roblox targets
        $roblox1 = ".ROBLOSECURITY" ascii wide
        $roblox2 = "ROBLOSECURITY" ascii wide
        $roblox3 = "roblox.com" ascii wide nocase

        // Browser targets (additional platform)
        $browser1 = "Google\\Chrome\\User Data" ascii wide nocase
        $browser2 = "Mozilla\\Firefox\\Profiles" ascii wide nocase
        $browser3 = "Login Data" ascii wide nocase
        $browser4 = "Cookies" ascii wide nocase

        // Exfiltration
        $exfil1 = "webhook" ascii wide nocase
        $exfil2 = "discord.com/api/webhooks" ascii wide
        $exfil3 = "request(" ascii
        $exfil4 = "HttpPost" ascii nocase
        $exfil5 = "upload" ascii nocase

        // Aggregation patterns (collecting all stolen data)
        $agg1 = "embed" ascii wide nocase
        $agg2 = "fields" ascii wide nocase
        $agg3 = "\\n" ascii
        $agg4 = "concat" ascii nocase
        $agg5 = "zip" ascii wide nocase

    condition:
        1 of ($exfil*) and
        (
            // Discord + Steam + Roblox
            (1 of ($discord*) and 1 of ($steam*) and 1 of ($roblox*)) or
            // Discord + Roblox + Browser
            (1 of ($discord*) and 1 of ($roblox*) and 1 of ($browser*)) or
            // All four platform categories
            (1 of ($discord*) and 1 of ($steam*) and 1 of ($browser*)) or
            // Steam + Roblox + Browser
            (1 of ($steam*) and 1 of ($roblox*) and 1 of ($browser*))
        )
}
