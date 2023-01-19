rule known_c2
{
	meta:
		author = "iam-py-test"
		description = "Detect files referencing known C2 servers"
	strings:
		$c2_1 = "116.202.5.101" // https://www.virustotal.com/gui/url/49799cb49d2c6a9696d3e911843b7098c52c274ec8fdbf25d0ba269e2b00a79a
		$c2_2 = "45.155.165.151" // https://www.virustotal.com/gui/file/29c7d7d36a0c8acec88ff7aa34adc0f9240270a85e330fd2336408e1f0d52c21
		$c2_3 = "88.198.106.9" // https://www.virustotal.com/gui/file/c695b3d55cafa00cfda4f4f50b42b6cd059d6db49184a48df22cfc9575a6d96c/detection 
		
		$fp_abpfilter = "[Adblock Plus 2.0]"
	condition:
		any of ($c2_*) and none of ($fp_*)
}