rule eicar_test_file
{
	meta:
		author = "iam-py-test"
		description = "Detect files containing the EICAR test file"
	strings:
		$e = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" nocase ascii wide
	condition:
		all of them
}