rule JScriptCom
{
	meta:
		author = "iam-py-test"
		description = "Detect files referencing .Net jsc.exe (Microsoft JScript Compiler)"
		example_file = "ba85b8a6507b9f4272229af0606356bab42af42f5ee2633f23c5e149c3fb9ca4"
		in_the_wild = true
	strings:
		$filelocation = "C:\\Windows\\Microsoft.NET\\Framewor"
		$applaunch = "\\jsc.exe" nocase
	condition:
		$filelocation and $applaunch
}