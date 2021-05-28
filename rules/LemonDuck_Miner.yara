rule LemonDuck_Miner
{
    meta:
        Author = "Kelly Shortridge"
        Repo = "https://github.com/rpetrich/patrolaroid/tree/main/rules"
        description = "Strings related to the Lemon Duck Miner"
        ref1 = "https://github.com/sophoslabs/IoCs/blob/master/Trojan-LDMiner.csv"

    strings:
        $string00 = "./xr -o lplp.ackng.com:444 --opencl --donate-level=1 --nicehash -B --http-host=0.0.0.0 --http-port=65529" fullword nocase wide ascii
        $string01 = "blackball" fullword nocase wide ascii
        $string02 = "nvd.zip" fullword nocase wide ascii
        $string03 = "xr.zip" fullword nocase wide ascii
        $string04 = "http://t.amynx.com/*" fullword nocase wide ascii
        $string05 = "http://d.ackng.com/*" fullword nocase wide ascii

    condition:
        any of them
}

rule LemonDuck_Lateral
{
     meta:
        Author = "Kelly Shortridge"
        Repo = "https://github.com/rpetrich/patrolaroid/rules"
        description = "Strings related to the Lemon Duck Miner's lateral movement behavior"
        ref1 = "https://news.sophos.com/en-us/2020/08/25/lemon_duck-cryptominer-targets-cloud-apps-linux/"

    strings:
        $string00 = "-f root/.ssh/known_hosts"
        $string01 = "export src=sshcopy"

    condition:
        all of them
}