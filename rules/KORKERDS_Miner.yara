rule KORKERDS_Miner
{
    meta:
        Author = "Kelly Shortridge"
        Repo = "https://github.com/rpetrich/patrolaroid/tree/main/rules"
        description = "Strings related to the KORKERDS Miner"
        ref1 = "https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/cryptocurrency-mining-malware-targets-linux-systems-uses-rootkit-for-stealth"
        ref2 = "https://documents.trendmicro.com/images/TEx/articles/linux-miner-rootkit-2.png"

    strings:
        $string00 = "/bin/.httpdns" fullword nocase wide ascii
        $string01 = "https://pastebin.com/raw/*" fullword nocase wide ascii
        $string02 = "/tmp/kworkerds" fullword nocase wide ascii
        $string03 = "minerxmr.ru" fullword nocase wide ascii
        $string04 = "downloadrunxm" fullword nocase wide ascii
        $string05 = "echo /usr/local/lib/libdns.so > /etc/ld.so.preload" fullword nocase wide ascii

    condition:
        any of them
}