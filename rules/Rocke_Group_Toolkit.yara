rule Rocke_Groupe_Toolkit
{
    meta:
        Author = "Kelly Shortridge"
        Repo = "https://github.com/rpetrich/patrolaroid/rules"
        description = "Strings related to the Rocke Group's toolkit"
        ref1 = "https://unit42.paloaltonetworks.com/malware-used-by-rocke-group-evolves-to-evade-detection-by-cloud-security-products/"

    strings:
        $string00 = "ps aux | grep -i '[a]liyun';" fullword nocase wide ascii
        $string01 = "https://pastebin.com/raw/*" fullword nocase wide ascii
        $string02 = "blog.sydwzl.cn" fullword nocase wide ascii
        $string03 = "echo /usr/local/lib/*.so >> /etc/ld.so.preload" fullword nocase wide ascii

    condition:
        any of them
}

