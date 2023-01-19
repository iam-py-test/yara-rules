rule reversed_executable
{
	meta:
		author = "iam-py-test"
		description = "Detect Windows PEEXEs which have been reversed"
	strings:
		$reversed_dosmode = "edom SOD ni nur eb tonnac margorp sihT!"
		$reversed_magic = { 5A 4D }
	condition:
		$reversed_dosmode and $reversed_magic at (filesize - 2)
}