import "hash"
rule known_hash
{
	meta:
		author = "iam-py-test"
		description = "Detect files which I have analyzed before (to avoid duplicates)"
	condition:
		hash.sha256(0,filesize) == "fb82a2488abb19f293df06778ea6059413f9f08e198a096eb5142f3503f1781b" or hash.sha256(0,filesize) == "f82cf1d06e116945ecc0c995dd10c9e76e62ecbb9d7f0964d212822498d7c032" or hash.sha256(0,filesize) == "f9eba50e0208700ad9c1c3761a50c855f86439328fdfb888e5f3e5d4cb81e46b" 
}