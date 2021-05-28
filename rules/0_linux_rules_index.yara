/* 
    This is the default ruleset for Patrolaroid, focused on Linux malware, ransomware, backdoors, toolkits, exploits, etc.
    It includes handcrafted rules by @swagitda as well as rules from the following sources:
    	* Deadbits: https://github.com/deadbits/yara-rules
    	* Reversing Labs: https://github.com/reversinglabs/reversinglabs-yara-rules
    	* Yara Rules Project: https://github.com/Yara-Rules/rules/

*/

include "./ACBackdoor_Malware.yara"
include "./Bew_Backdoor_Miner.yara"
include "./Chicken_DOS.yara"
include "./Dacls_Trojan.yara"
include "./Derubsi_Malware.yara"
include "./DirtyCow_Exploit.yara"
include "./ELF_Malware_Strings.yara"
include "./Equation_Group_Toolkit.yara"
include "./Equation_Group_Toolkit_2.yara"
include "./Equation_Group_Toolkit_3.yara"
include "./Erebus_Ransomware.yara"
include "./EvilGnome_Malware.yara"
include "./GodLua_Malware.yara"
include "./GreedyAntd_Malware.yara"
include "./Helios_Malware.yara"
include "./KillDisk_Ransomware.yara"
include "./KORKERDS_Miner.yara"
include "./Kraken_Ransomware.yara"
include "./LemonDuck_Miner.yara"
include "./LuckyJoe_Ransomware.yara"
include "./Mandibule_Toolkit.yara"
include "./Mirai_Okiru_Malware.yara"
include "./Mirai_Satori_Malware.yara"
include "./Misc_Malware.yara"
include "./Moose_Malware.yara"
include "./Op_Windigo_Malware.yara"
include "./Rebirth_Vulcan_Malware.yara"
include "./RedGhost_Malware.yara"
include "./Rocke_Group_Toolkit.yara"
include "./Sofacy_Backdoor.yara"
include "./TinyShell_Backdoor.yara"
include "./Thor_Toolkit.yara"
include "./Thor_Webshells.yara"
include "./Torte_ELF_Malware.yara"
include "./Vit_Virus.yara"
include "./WatchDog_Malware.yara"
include "./Winnti_Malware.yara"
include "./XMRig_Miner_Strings.yara"