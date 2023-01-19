rule encoded_http
{
	meta:
		author = "iam-py-test"
		description = "Detect files (mainly JavaScript) containing http or https encoded in some shape or form"
	strings:
		$http_enc_unicode = "h\\164tp\\u0073://"
		$http_enc_unicode_2 = "ht\\x74p\\163://"
		$http_enc_unicode_3 = "http:\\x2f"
		$http_enc_unicode_4 = "ht\\u0074\\160\\163:/\\x2f"
	condition:
		any of them
}