rule safemode_key
{
	meta:
		author = "iam-py-test"
		description = "Detect files referencing the safe mode registry key"
	strings:
		$r = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot" ascii wide
	condition:
		any of them
	
}