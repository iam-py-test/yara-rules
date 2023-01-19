rule ASPNET_compile
{
	meta:
		author = "iam-py-test"
		description = "Detect files referencing ASP.NET Compilation Tool"
		in_the_wild = true
		// yarahub data
		date = "2022-11-29"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
	strings:
		$filelocation = "C:\\Windows\\Microsoft.NET\\Framewor" ascii wide
		$asp = "\\aspnet_compiler.exe" nocase ascii wide
	condition:
		$filelocation and $asp
}