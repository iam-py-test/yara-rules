rule ie_policy_regkey
{
	meta:
		author = "iam-py-test"
		description = "Detect references to registry keys connected to Internet Explorer policies"
	strings:
		$s1 = "\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer" nocase ascii wide
	condition:
		any of them
}