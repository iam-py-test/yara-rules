rule antivirus_service_stop
{
	meta:
		author = "iam-py-test"
		description = "Detect files stopping, disabling, or deleting services used by security software"
	strings:
		$mb1 = "get-service -displayname \"MBAMService\" | stop-service" nocase ascii wide
		$mb2 = "Get-Service -Name \"MBAMService\" | Stop-Service" nocase ascii wide
		$mb3 = "Get-Service MBAMService | Set-Service -StartupType Disabled"
	condition:
		any of them
}