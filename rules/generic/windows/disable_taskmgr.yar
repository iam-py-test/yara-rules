rule disable_taskmgr
{
	meta:
		author = "iam-py-test"
		description = "Detect applications disabling task manager"
	strings:
		$pol_key = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii wide
		$pol_wow_key = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii wide
		$value = "DISABLETASKMGR" nocase
	condition:
		any of ($pol*) and $value
}