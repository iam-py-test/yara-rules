rule Base64_decoding
{
	meta:
		author = "iam-py-test"
		description = "Detect scripts which are decoding base64 encoded data (mainly Python, may apply to other languages)"
		example_file = "dd1fa3398a9cb727677501fd740d47e03f982621101cc7e6ab8dac457dca9125"
		false_positives = "Programs using base64 for non-malware purposes, programs encoding base64"
	strings:
		$base64_lib_import = "import base64"
		$base64_lib_b64decode = ".b64decode("
		$system_lib_function = "Convert.FromBase64String"
	condition:
		any of them
}