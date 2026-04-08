/*
    YARA Rules - Information Stealers
    Targets credential and data stealers bundled with game cheats
*/

rule RedLine_Stealer
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects RedLine information stealer"
        severity = 10
        date = "2026-04-03"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer"

    strings:
        $s1 = "RedLine" ascii wide
        $s2 = "RedLine.Client" ascii
        $s3 = "RedLine.Models" ascii
        $s4 = "RedLine.Logic" ascii

        $browser1 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii wide
        $browser2 = "\\Google\\Chrome\\User Data\\Default\\Cookies" ascii wide
        $browser3 = "\\Google\\Chrome\\User Data\\Default\\Web Data" ascii wide
        $browser4 = "\\Mozilla\\Firefox\\Profiles" ascii wide

        $wallet1 = "\\Electrum\\wallets" ascii wide
        $wallet2 = "\\Ethereum\\keystore" ascii wide
        $wallet3 = "\\Exodus\\exodus.wallet" ascii wide
        $wallet4 = "\\Atomic\\Local Storage\\leveldb" ascii wide
        $wallet5 = "\\com.liberty.jaxx\\IndexedDB" ascii wide

        $func1 = "ScanBrowsers" ascii
        $func2 = "ScanWallets" ascii
        $func3 = "ScanFTP" ascii
        $func4 = "ScanVPN" ascii
        $func5 = "GrabScreenshot" ascii
        $func6 = "GatherHardwareInfo" ascii

        $net1 = "SOAP-ENV" ascii
        $net2 = "RecordHeaderField" ascii
        $net3 = "ConnectionInformationDetail" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($s*) and 2 of ($func*)) or
            (1 of ($s*) and 3 of ($browser*) and 2 of ($wallet*)) or
            (2 of ($net*) and 2 of ($func*) and 2 of ($browser*))
        )
}

rule Raccoon_Stealer
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects Raccoon stealer"
        severity = 10
        date = "2026-04-03"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.raccoonstealer"

    strings:
        $s1 = "Raccoon Stealer" ascii wide nocase
        $s2 = "rill_" ascii

        $lib1 = "sqlite3.dll" ascii wide
        $lib2 = "nss3.dll" ascii wide
        $lib3 = "mozglue.dll" ascii wide
        $lib4 = "freebl3.dll" ascii wide
        $lib5 = "softokn3.dll" ascii wide

        $cfg1 = "machineId=" ascii
        $cfg2 = "configId=" ascii
        $cfg3 = "rcid=" ascii

        $path1 = "\\passwords.txt" ascii wide
        $path2 = "\\cookies.txt" ascii wide
        $path3 = "\\autofill.txt" ascii wide
        $path4 = "\\cards.txt" ascii wide
        $path5 = "\\System Info.txt" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            (1 of ($s*) and 3 of ($lib*)) or
            (3 of ($lib*) and 2 of ($cfg*)) or
            (3 of ($lib*) and 3 of ($path*))
        )
}

rule Vidar_Stealer
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects Vidar information stealer"
        severity = 10
        date = "2026-04-03"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vidar"

    strings:
        $lib1 = "vcruntime140.dll" ascii wide
        $lib2 = "msvcp140.dll" ascii wide
        $lib3 = "nss3.dll" ascii wide
        $lib4 = "sqlite3.dll" ascii wide

        $path1 = "\\files\\Autofill" ascii wide
        $path2 = "\\files\\Cookies" ascii wide
        $path3 = "\\files\\CC" ascii wide
        $path4 = "\\files\\History" ascii wide
        $path5 = "\\files\\Downloads" ascii wide

        $cfg_delim = { 31 7C 31 7C 31 7C }  // "1|1|1|" config format

        $func1 = "hwid" ascii
        $func2 = "os=" ascii
        $func3 = "platform=" ascii
        $func4 = "profile=" ascii
        $func5 = "user=" ascii

        $wallet_v1 = "\\Wallets\\" ascii wide
        $wallet_v2 = "wallet.dat" ascii wide
        $wallet_v3 = "\\Ethereum\\" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            (3 of ($lib*) and 3 of ($path*)) or
            ($cfg_delim and 2 of ($lib*) and 2 of ($path*)) or
            (3 of ($path*) and 2 of ($wallet_v*) and 2 of ($func*))
        )
}

rule Generic_Browser_Credential_Stealer
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects generic browser credential stealing patterns"
        severity = 8
        date = "2026-04-03"
        reference = "internal"

    strings:
        // Chrome paths
        $chrome1 = "\\Google\\Chrome\\User Data" ascii wide
        $chrome2 = "Login Data" ascii wide
        $chrome3 = "Local State" ascii wide
        $chrome4 = "encrypted_key" ascii wide

        // Firefox paths
        $ff1 = "\\Mozilla\\Firefox\\Profiles" ascii wide
        $ff2 = "logins.json" ascii wide
        $ff3 = "key4.db" ascii wide
        $ff4 = "cert9.db" ascii wide

        // Edge paths
        $edge1 = "\\Microsoft\\Edge\\User Data" ascii wide

        // Opera
        $opera1 = "\\Opera Software\\Opera Stable" ascii wide

        // Brave
        $brave1 = "\\BraveSoftware\\Brave-Browser\\User Data" ascii wide

        // Decryption indicators
        $decrypt1 = "CryptUnprotectData" ascii
        $decrypt2 = "BCryptDecrypt" ascii
        $decrypt3 = "AesGcm" ascii wide

        // SQLite usage for credential extraction
        $sql1 = "SELECT origin_url, username_value, password_value FROM logins" ascii wide nocase
        $sql2 = "SELECT host_key, name, encrypted_value FROM cookies" ascii wide nocase
        $sql3 = "SELECT name, value FROM autofill" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (
            (1 of ($sql*) and 1 of ($decrypt*)) or
            (3 of ($chrome*) and 1 of ($decrypt*)) or
            (2 of ($ff*) and 1 of ($chrome*) and 1 of ($decrypt*)) or
            (1 of ($chrome*) and 1 of ($edge*) and 1 of ($brave*) and 1 of ($decrypt*))
        )
}

rule Generic_Crypto_Wallet_Stealer
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects crypto wallet stealing behavior"
        severity = 9
        date = "2026-04-03"
        reference = "internal"

    strings:
        $w1 = "\\Electrum\\wallets" ascii wide
        $w2 = "\\Ethereum\\keystore" ascii wide
        $w3 = "\\Exodus\\exodus.wallet" ascii wide
        $w4 = "\\Atomic\\Local Storage" ascii wide
        $w5 = "\\Guarda\\Local Storage" ascii wide
        $w6 = "\\Coinomi\\Coinomi\\wallets" ascii wide
        $w7 = "\\Binance\\" ascii wide
        $w8 = "wallet.dat" ascii wide
        $w9 = "\\Phantom\\Local Storage" ascii wide
        $w10 = "\\MetaMask\\Local Storage" ascii wide

        // Browser extension IDs for crypto wallets
        $ext1 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii  // MetaMask
        $ext2 = "ibnejdfjmmkpcnlpebklmnkoeoihofec" ascii  // TronLink
        $ext3 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii  // Phantom

        $copy1 = "CopyFileA" ascii
        $copy2 = "CopyFileW" ascii
        $copy3 = "File.Copy" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            (4 of ($w*) and 1 of ($copy*)) or
            (2 of ($ext*) and 2 of ($w*)) or
            (5 of ($w*))
        )
}

rule Discord_Token_Stealer
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects Discord token stealing patterns common in gaming malware"
        severity = 8
        date = "2026-04-03"
        reference = "internal"

    strings:
        $path1 = "\\discord\\Local Storage\\leveldb" ascii wide
        $path2 = "\\discordcanary\\Local Storage\\leveldb" ascii wide
        $path3 = "\\discordptb\\Local Storage\\leveldb" ascii wide
        $path4 = "\\Discord\\Local Storage" ascii wide

        $token_re1 = "[\"]?[MN][A-Za-z\\d]{23,}" ascii wide
        $token_re2 = "mfa\\." ascii wide

        $api1 = "discord.com/api" ascii wide
        $api2 = "discordapp.com/api" ascii wide

        $webhook1 = "discord.com/api/webhooks" ascii wide
        $webhook2 = "discordapp.com/api/webhooks" ascii wide

        $func1 = "getToken" ascii wide nocase
        $func2 = "grabToken" ascii wide nocase
        $func3 = "tokenGrabber" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($path*) and 1 of ($api*)) or
            (1 of ($webhook*) and 1 of ($path*)) or
            (1 of ($func*) and 1 of ($path*)) or
            (2 of ($path*) and 1 of ($func*))
        )
}

rule Steam_Session_Stealer
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects Steam session/credential stealing behavior"
        severity = 8
        date = "2026-04-03"
        reference = "internal"

    strings:
        $steam1 = "\\Steam\\config\\loginusers.vdf" ascii wide
        $steam2 = "\\Steam\\ssfn" ascii wide
        $steam3 = "\\Steam\\config\\SteamAppData.vdf" ascii wide
        $steam4 = "\\Steam\\config\\config.vdf" ascii wide

        $reg1 = "Software\\Valve\\Steam" ascii wide
        $reg2 = "SteamPath" ascii wide

        $file1 = "ssfn*" ascii wide
        $file2 = "loginusers.vdf" ascii wide
        $file3 = "SteamAppData.vdf" ascii wide

        $copy1 = "CopyFile" ascii
        $copy2 = "File.Copy" ascii
        $zip1 = "ZipFile" ascii
        $zip2 = "CreateFromDirectory" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($steam*) and 1 of ($copy*)) or
            (1 of ($reg*) and 2 of ($file*) and 1 of ($copy*)) or
            (2 of ($steam*) and 1 of ($zip*))
        )
}
