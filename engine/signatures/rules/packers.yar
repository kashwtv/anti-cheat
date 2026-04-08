/*
    YARA Rules - Packer/Protector Identification
    INFORMATIONAL ONLY - These are NOT flagged as malicious.
    Packers are commonly used by cheat developers to protect their code.
*/

rule UPX_Packed : packer
{
    meta:
        author = "AntiCheat Engine"
        description = "File is packed with UPX"
        severity = 1
        date = "2026-04-03"
        info = "INFORMATIONAL - Not malicious"

    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX2" ascii
        $sig = "UPX!" ascii
        $ver = "UPX executable packer" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            ($upx0 and $upx1) or
            $sig or
            $ver
        )
}

rule Themida_Protected : packer
{
    meta:
        author = "AntiCheat Engine"
        description = "File is protected with Themida/WinLicense"
        severity = 2
        date = "2026-04-03"
        info = "INFORMATIONAL - Common in cheat software"

    strings:
        $sec1 = ".themida" ascii
        $sec2 = ".winlice" ascii
        $str1 = "Themida" ascii wide
        $str2 = "WinLicense" ascii wide
        $str3 = "Oreans Technologies" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (1 of them)
}

rule VMProtect_Protected : packer
{
    meta:
        author = "AntiCheat Engine"
        description = "File is protected with VMProtect"
        severity = 2
        date = "2026-04-03"
        info = "INFORMATIONAL - Common in cheat software"

    strings:
        $sec1 = ".vmp0" ascii
        $sec2 = ".vmp1" ascii
        $sec3 = ".vmp2" ascii
        $str1 = "VMProtect" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (1 of them)
}

rule Enigma_Protected : packer
{
    meta:
        author = "AntiCheat Engine"
        description = "File is protected with Enigma Protector"
        severity = 2
        date = "2026-04-03"
        info = "INFORMATIONAL"

    strings:
        $sec1 = ".enigma1" ascii
        $sec2 = ".enigma2" ascii
        $str1 = "Enigma Protector" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (1 of them)
}

rule ASPack_Packed : packer
{
    meta:
        author = "AntiCheat Engine"
        description = "File is packed with ASPack"
        severity = 1
        date = "2026-04-03"
        info = "INFORMATIONAL"

    strings:
        $sec1 = ".aspack" ascii
        $sec2 = ".adata" ascii
        $str1 = "ASPack" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (1 of them)
}

rule ConfuserEx_Obfuscated : packer
{
    meta:
        author = "AntiCheat Engine"
        description = "File is obfuscated with ConfuserEx"
        severity = 2
        date = "2026-04-03"
        info = "INFORMATIONAL - Common .NET obfuscator"

    strings:
        $s1 = "ConfuserEx" ascii wide
        $s2 = "Confuser.Core" ascii
        $s3 = "ConfusedByAttribute" ascii

    condition:
        uint16(0) == 0x5A4D and
        (1 of them)
}
