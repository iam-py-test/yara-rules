rule Image_File_Exec_Options
{
	meta:
		author = "iam-py-test"
		description = "Detect files referencing Windows Image File Execution Options"
	strings:
		$wnt_ifeo = "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
		$wow6432_ifeo = "\\Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
	condition:
		any of them
}