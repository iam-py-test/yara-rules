import "pe"

rule detect_ff4ef52f1b88c67c5b09f424a8e02208
{
	meta:
		author = "iam-py-test"
		description = "Detect files similar to a known malware sample (ff4ef52f1b88c67c5b09f424a8e02208)"
		example = "ff4ef52f1b88c67c5b09f424a8e02208"
	strings:
		$m1 = "Copyright (C) 2022, somoklos"
		$m2 = "polpwaoce.iwe"
		$m3 = "10440ED2"
	condition:
		pe.pdb_path == "C:\\lij_sotizib\\zil\\nutomahojolami_hisez.pdb" or 2 of ($m*)
}