rule processhacker
{
	meta:
		author = "iam-py-test"
		description = "Process Hacker is a open source tool for Windows. While this tool is benign, it is sometimes abused"
		date = "2022-11-21"
	strings:
		// the main process hacker file
		$ph1 = "Process Hacker"
		$ph2 = "\\x86\\ProcessHacker.exe"
		$ph3 = "\\Release32\\ProcessHacker.exe"
		$ph4 = "KProcessHacker"
		$ph5 = "A_ProcessHacker"
		$ph6 = "Hidden Processes.txt"
		$ph7 = "ProcessHacker.exe"
		$ph8 = "ProcessHacker.sig"
		$ph9 = "\\BaseNamedObjects\\ProcessHacker2Mutant"
		$ph10 = "sourceforge.net/project/project_donations.php?group_id=242527"
		
		// kprocesshacker driver
		$kph1 = "d:\\projects\\processhacker2\\kprocesshacker\\bin\\amd64\\kprocesshacker.pdb"
		$kph2 = "kprocesshacker.sys"
	condition:
		2 of ($ph*) or any of ($kph*)
}