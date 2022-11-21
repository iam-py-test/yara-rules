rule kill_explorer
{
	meta:
		author = "iam-py-test"
		description = "Detect files killing explorer.exe"
	strings:
		$malware_taskkill = "taskkill /F /IM explorer.exe" nocase
	condition:
		any of ($malware_*)
		
}