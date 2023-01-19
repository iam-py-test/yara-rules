//commented out as to avoid throwing off the "all rules" rule
//rule pemagic
//{
//	meta:
//		author = "iam-py-test"
//		description = "Detect files starting with MZ"
//	strings:
//		$hex_mz = { 4D 5A }
//	condition:
//		$hex_mz at 0
//}