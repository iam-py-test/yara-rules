rule reference_odd_file_path
{
	meta:
		author = "iam-py-test"
		description = "Detect references to odd file paths"
	strings:
		$p1 = "\\AppData\\Roaming\\svchost.exe" ascii wide
		$p2 = "\\AppData\\Roaming\\sihost.exe" ascii wide
		$p3 = "\\Startup\\Microsoft Corporation.exe" nocase ascii wide
		$p4 = "\\ProgramData\\mzvgmp.bat" ascii wide
		$p5 = "\\SVCUPDATER.EXE" nocase ascii wide
		$p6 = "\\Windows\\Speech\\services.exe" ascii wide
		$p7 = "\\Windows\\Runtime Service.exe" ascii wide
		$p8 = "\\NETSVC4.EXE" nocase ascii wide
		$p9 = "\\AppData\\Local\\Updates\\Run.vbs" ascii wide
		$p10 = "\\Pictures\\SearchIndexer.exe" ascii wide
		$p11 = "\\svchostf.exe" ascii wide
		$p12 = "\\WindowsService.exe" ascii wide
		$p13 = "\\Music\\lsass.exe" ascii wide
		$p14 = "\\MicrosoftHost.exe" ascii wide
		$p15 = /\\Fonts\\[a-zA-Z0-9]*\.exe/
		$p16 = "\\H35c27gu.exe" ascii wide
		$p17 = "\\qEdJzM2d.exe" ascii wide nocase
		$p18 = "\\Y9QuxeJCZGmxxOGMOV2sEXu9.exe" ascii wide nocase
		
	condition:
		any of them
		
}