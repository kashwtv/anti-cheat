rule XMRig_Miner
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects XMRig cryptocurrency miner"
        severity = 8
        date = "2026-04-03"

    strings:
        $s1 = "xmrig" ascii wide nocase
        $s2 = "XMRig" ascii wide
        $s3 = "stratum+tcp://" ascii wide
        $s4 = "stratum+ssl://" ascii wide
        $s5 = "cryptonight" ascii wide nocase
        $s6 = "randomx" ascii wide nocase
        $s7 = "hashrate" ascii wide nocase
        $s8 = "mining" ascii wide
        $pool1 = "pool.minexmr.com" ascii wide
        $pool2 = "xmrpool.eu" ascii wide
        $pool3 = "pool.hashvault.pro" ascii wide
        $pool4 = "gulf.moneroocean.stream" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($s*) and 1 of ($pool*)) or
            ($s3 and 2 of ($s*)) or
            ($s4 and 2 of ($s*)) or
            (3 of ($s*))
        )
}

rule Generic_CryptoMiner
{
    meta:
        author = "AntiCheat Engine"
        description = "Detects generic cryptocurrency mining behavior"
        severity = 7
        date = "2026-04-03"

    strings:
        $mine1 = "stratum+tcp://" ascii wide
        $mine2 = "stratum+ssl://" ascii wide
        $mine3 = "mining.subscribe" ascii wide
        $mine4 = "mining.authorize" ascii wide
        $mine5 = "mining.submit" ascii wide
        $mine6 = "hashrate" ascii wide nocase
        $mine7 = "--donate-level" ascii wide
        $mine8 = "worker" ascii wide
        $coin1 = "monero" ascii wide nocase
        $coin2 = "bitcoin" ascii wide nocase
        $coin3 = "ethereum" ascii wide nocase
        $algo1 = "cryptonight" ascii wide nocase
        $algo2 = "randomx" ascii wide nocase
        $algo3 = "ethash" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (
            (1 of ($mine1, $mine2) and 2 of ($mine*)) or
            (2 of ($mine*) and 1 of ($algo*)) or
            (1 of ($mine1, $mine2) and 1 of ($coin*) and 1 of ($algo*))
        )
}
