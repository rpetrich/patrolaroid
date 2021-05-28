/* Source: https://gist.github.com/GelosSnake/c2d4d6ef6f93ccb7d3afb5b1e26c7b4e */

rule MinerGate
{
strings:
$a1 = "minergate.com"
condition:
$a1
}

rule MoneroOrg
{
strings:
$a1 = "POOL.MONERO.ORG"
$a2 = "pool.monero.org"
condition:
$a1 or $a2
}

rule cryptonotepool
{
strings:
$a1 = "cryptonotepool.org.uk"
condition:
$a1
}

rule minexmr
{
strings:
$a1 = "minexmr.com"
$a2 = "x.opmoner.com"
condition:
$a1 or $a2
}

rule monerocryptopoolfr
{
strings:
$a1 = "monero.crypto-pool.fr"
condition:
$a1
}

rule monerobackuppoolcom
{
strings:
$a1 = "monero.backup-pool.com"
condition:
$a1
}

rule monerohashcom
{
strings:
$a1 = "monerohash.com"
condition:
$a1
}

rule mropooltobe
{
strings:
$a1 = "mro.poolto.be"
condition:
$a1
}

rule moneroxminingpoolcom
{
strings:
$a1 = "monero.xminingpool.com"
condition:
$a1
}

rule xmrprohashnet
{
strings:
$a1 = "xmr.prohash.net"
condition:
$a1
}

rule dwarfpoolcom
{
strings:
$a1 = "dwarfpool.com"
condition:
$a1
}

rule xmrcryptopoolsorg
{
strings:
$a1 = "xmr.crypto-pools.org"
condition:
$a1
}

rule moneronet
{
strings:
$a1 = "monero.net"
condition:
$a1
}

rule hashinvestnet
{
strings:
$a1 = "hashinvest.net"
condition:
$a1
}

rule stratum_tcp_general
{
strings:
$a1 = "stratum+tcp"
condition:
$a1
}