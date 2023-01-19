rule proxyenable
{
	meta:
		author = "iam-py-test"
		description = "Detect files referencing the registry key & value to enable/disable use of proxies on Windows"
	strings:
		$k1 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" nocase ascii wide
		$k2 = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" nocase ascii wide
		$v1 = "PROXYENABLE" nocase ascii wide
	condition:
		any of ($k*) and $v1
}