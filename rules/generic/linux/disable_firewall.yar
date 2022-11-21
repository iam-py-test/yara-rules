rule Disable_Linux_Firewall
{
	meta:
		author = "iam-py-test"
		description = "Detect .sh scripts disabling Linux firewalls"
		example_file = "1d34f7826010b37f2a788b018e3e94c091c95b155a07517d7f5aac42182c5129"
	strings:
		$iptables_flush = "iptables -F"
		$iptables_flush_fullname = "iptables --flush" nocase
		$systemctl_stop_firewalld = "systemctl stop firewalld"
		$systemctl_disable_firewalld = "systemctl disable firewalld"
		$iptables_stop = "service iptables stop"
		$ufw_allow = "ufw allow "
	condition:
		any of them
}