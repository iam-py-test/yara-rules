rule iexplorer_remcos
{
	meta:
		author = "iam-py-test"
		description = "Detect iexplorer being taken over by Remcos"
	strings:
		$ie1 = "C:\\Program Files(x86)\\Internet Explorer" ascii wide
		$ie2 = "ieinstal.exe" ascii wide
		$ie3 = "ielowutil.exe" ascii wide
		
		$r1 = "Remcos Agent initialized"
		$r2 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f" ascii wide
		$r3 = "Remcos restarted by watchdog!" ascii wide
		$r4 = "Watchdog module activated" ascii wide
		$r5 = "Watchdog launch failed!" ascii wide
		$r6 = "BreakingSecurity.net" ascii wide
	condition:
		2 of ($ie*) and any of ($r*)
}