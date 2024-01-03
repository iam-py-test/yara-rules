rule sys_info
{
	meta:
		description = "Detect files getting system information, either for legitimate or malicious purposes"
	strings:
		$ipconfigall = "ipconfig /all"
		$ipconfigallexe = "ipconfig.exe /all"
		$whoamiall = "whoami /all"
		$mountvol = "mountvol"
		$systeminfo = "systeminfo"
		$driverquery = "driverquery"
		$regqueryhkcurun = "reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
	condition:
		any of them
}