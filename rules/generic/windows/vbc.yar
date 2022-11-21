rule vbc
{
	meta:
		author = "iam-py-test"
		description = "Detect files referencing .Net vbc.exe (Microsoft Visual Basic Compiler)"
		example_file = "24d5e7bf693f7390c33f2de7c1634c7973ca1b8d13cb7e7cf10c233250856473"
		in_the_wild = true
		date = "2022-11-21"
	strings:
		$filelocation = "C:\\Windows\\Microsoft.NET\\Framewor" ascii wide
		$vbc = "\\vbc.exe" ascii wide
	condition:
		$filelocation and $vbc
}