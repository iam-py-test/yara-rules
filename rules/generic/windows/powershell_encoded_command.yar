rule powershell_encoded_command
{
	meta:
		author = "iam-py-test"
		description = "Detect base64 encoded commands being sent to PowerShell"
	strings:
		$p1 = "powershell -WindowStyle Hidden -EncodedCommand " nocase ascii wide
		$p2 = "powershell -EncodedCommand " nocase ascii wide
		$p3 = "powershell.exe -EncodedCommand" nocase ascii wide
		$p4 = "powershell.exe -WindowStyle Hidden -EncodedCommand " nocase ascii wide
		$p5 = "powershell -enc " nocase ascii
		$p6 = "powershell.exe -enc" nocase ascii
	condition:
		any of them
}