rule Disable_Defender
{
	meta:
		author = "iam-py-test"
		description = "Detect files disabling or modifying Windows Defender, Windows Firewall, or Microsoft Smartscreen"
		// Yarahub date
		yarahub_uuid = "1fcd3702-cf5b-47b4-919d-6372c5412151"
		date = "2022-11-19"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "799a7f1507e5e7328081a038987e9a6f"
		yarahub_author_twitter = "@iam_py_test"
	strings:
		// Windows Defender
		$defender_policies_reg_key = "\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"
		$defender_powershell_pupprotection_Force = "Set-MpPreference -Force -PUAProtection"
		$defender_powershell_pupprotection = "Set-MpPreference -PUAProtection"
		$defender_features_reg_key = "\\SOFTWARE\\Microsoft\\Windows Defender\\Features"
		$defender_disable_autoexclusions_powershell_force = "Set-MpPreference -Force -DisableAutoExclusions"
		$defender_disable_autoexclusions_powershell = "Set-MpPreference -DisableAutoExclusions"
		$defender_disable_MAPS_reporting_force = "Set-MpPreference -Force -MAPSReporting"
		$defender_disable_MAPS_reporting = "Set-MpPreference -MAPSReporting"
		$defender_disable_submit_samples_force = "Set-MpPreference -Force -SubmitSamplesConsent"
		$defender_disable_submit_samples = "Set-MpPreference -SubmitSamplesConsent"
		$defender_disable_realtime_force = "Set-MpPreference -Force -DisableRealtimeMonitoring"
		$defender_disable_realtime = "Set-MpPreference -DisableRealtimeMonitoring"
		$defender_disable_IPS_force = "Set-MpPreference -Force -DisableIntrusionPreventionSystem"
		$defender_disable_IPS = "Set-MpPreference -DisableIntrusionPreventionSystem"
		$defender_wd_filter_driver = "%SystemRoot%\\System32\\drivers\\WdFilter.sys"
		$defender_wdboot_driver = "%SystemRoot%\\System32\\drivers\\WdBoot.sys"
		$defender_net_stop_windefend = "net stop windefend" nocase
		$defender_net_stop_SecurityHealthService = "net stop SecurityHealthService" nocase
		$defender_powershell_exclusionpath = "Add-MpPreference -ExclusionPath"
		$defender_powershell_exclusionext = "Add-MpPreference -ExclusionExtension"
		$defender_powershell_exclusionprocess = "Add-MpPreference -ExclusionProcess"
		$defender_powershell_exclusionip = "Add-MpPreference -ExclusionIpAddress"
		$defender_uilockdown = "Set-MpPreference -UILockdown"
		$defender_uilockdown_force = "Set-MpPreference -Force -UILockdown"
		$defender_securitycenter = "\\SOFTWARE\\Microsoft\\Windows Defender Security Center\\"
		
		// Windows firewall
		$firewall_netsh_disable = "netsh advfirewall set allprofiles state off"
		$firewall_reg_key = "\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\"
		$firewall_sharedaccess_reg_key = "\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\"
		
		// Microsoft Windows Malicious Software Removal Tool
		$MRT_reg_key = "\\SOFTWARE\\Policies\\Microsoft\\MRT"
		$MRT_reg_key_wow64 = "\\SOFTWARE\\WOW6432NODE\\POLICIES\\MICROSOFT\\MRT"
		
		// Edge
		$edge_phishing_filter = "\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter"
		
		// Internet Explorer
		$ie_phishing_filter = "\\SOFTWARE\\Microsoft\\Internet Explorer\\PhishingFilter"

	condition:
		any of them
}