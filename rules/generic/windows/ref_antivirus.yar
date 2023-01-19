rule ref_antivirus
{
	meta:
		author = "iam-py-test"
		description = "Detect files referencing files and directories used by security software"
	strings:
		$d1 = "C:\\Program Files\\Lavasoft" nocase ascii wide
		$d2 = "C:\\Program Files\\Mcafee" nocase ascii wide
		$d3 = "C:\\Program Files\\Trend Micro" nocase ascii wide
		$d4 = "C:\\Program Files\\kaspersky" nocase ascii wide
		$d5 = "C:\\Program Files\\Malwarebytes" nocase ascii wide
		$d6 = "C:\\Program Files (x86)\\Trend Micro" nocase ascii wide
		$d7 = "C:\\Program Files\\ESET\\ESET Security" nocase ascii wide
		$d8 = "C:\\Program Files\\Common Files\\McAfee" nocase ascii wide
		$d9 = "C:\\Program Files\\AVG"
		$d10 = "C:\\Program Files\\Avast Software"
	condition:
		3 of ($d*)
}