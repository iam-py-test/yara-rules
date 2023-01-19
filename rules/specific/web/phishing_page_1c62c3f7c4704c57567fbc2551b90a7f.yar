rule phishing_page_1c62c3f7c4704c57567fbc2551b90a7f 
{
	meta:
		author = "iam-py-test"
		description = "Detect files similar to 1c62c3f7c4704c57567fbc2551b90a7f"
	strings:
		$p1 = "h\\164tp\\u0073://\\u0031drv.m\\163/x/"
	condition:
		2 of them
}