
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

rule python_exec
{
	meta:
		author = "iam-py-test"
		description = "Detect Python scripts using exec"
		example_file = "dd1fa3398a9cb727677501fd740d47e03f982621101cc7e6ab8dac457dca9125"
		false_positives = "Programs using exec for non-malware purposes, programs in other languages"
	strings:
		$exec_function = "exec("
		// don't match PE files 
		$DOS_program = "!This program cannot be run in DOS mode."
		$hex_mz = { 4D 5A }
	condition:
		$exec_function and not ($DOS_program or $hex_mz at 0)
}

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

rule AppLaunch
{
	meta:
		author = "iam-py-test"
		description = "Detect files referencing .Net AppLaunch.exe"
		example_file = "ba85b8a6507b9f4272229af0606356bab42af42f5ee2633f23c5e149c3fb9ca4"
		new_example_file = "cda99e504a122208862739087cf16b4838e9f051acfcbeb9ec794923b414c018"
		in_the_wild = true
		// yarahub data
		date = "2022-11-17"
		yarahub_uuid = "613f8ac7-a5f3-4167-bbcd-4dbfd4c8ba67"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "7dbfe0186e52ef2da13079f6d5b800d7"
	strings:
		$filelocation = "C:\\Windows\\Microsoft.NET\\Framewor" ascii wide
		$applaunch = "\\AppLaunch.exe" nocase ascii wide
	condition:
		$filelocation and $applaunch
}

rule ASPNET_compile
{
	meta:
		author = "iam-py-test"
		description = "Detect files referencing ASP.NET Compilation Tool"
		in_the_wild = true
		// yarahub data
		date = "2022-11-29"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
	strings:
		$filelocation = "C:\\Windows\\Microsoft.NET\\Framewor" ascii wide
		$asp = "\\aspnet_compiler.exe" nocase ascii wide
	condition:
		$filelocation and $asp
}

rule Disable_Defender
{
	meta:
		author = "iam-py-test"
		description = "Detect files disabling or modifying Windows Defender, Windows Firewall, or Microsoft Smartscreen"
		false_positives = "Files modifying Defender for legitimate purposes, files containing registry keys related to Defender (i.e. diagnostic tools)"
		// Yarahub data
		yarahub_uuid = "1fcd3702-cf5b-47b4-919d-6372c5412151"
		date = "2022-11-19"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "799a7f1507e5e7328081a038987e9a6f"
		yarahub_author_twitter = "@iam_py_test"
	strings:
		// Windows Defender
		$defender_policies_reg_key = "\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" ascii wide
		$defender_powershell_pupprotection_Force = "Set-MpPreference -Force -PUAProtection" ascii wide
		$defender_powershell_pupprotection = "Set-MpPreference -PUAProtection" ascii wide
		$defender_reg_key = "\\SOFTWARE\\Microsoft\\Windows Defender" ascii wide
		$defender_disable_autoexclusions_powershell_force = "Set-MpPreference -Force -DisableAutoExclusions" ascii wide
		$defender_disable_autoexclusions_powershell = "Set-MpPreference -DisableAutoExclusions" ascii wide
		$defender_disable_MAPS_reporting_force = "Set-MpPreference -Force -MAPSReporting" ascii wide
		$defender_disable_MAPS_reporting = "Set-MpPreference -MAPSReporting" ascii wide
		$defender_disable_submit_samples_force = "Set-MpPreference -Force -SubmitSamplesConsent" ascii wide
		$defender_disable_submit_samples = "Set-MpPreference -SubmitSamplesConsent" ascii wide
		$defender_disable_realtime_force = "Set-MpPreference -Force -DisableRealtimeMonitoring" ascii wide
		$defender_disable_realtime = "Set-MpPreference -DisableRealtimeMonitoring" ascii wide
		$defender_disable_IPS_force = "Set-MpPreference -Force -DisableIntrusionPreventionSystem" ascii wide
		$defender_disable_IPS = "Set-MpPreference -DisableIntrusionPreventionSystem" ascii wide
		$defender_wd_filter_driver = "%SystemRoot%\\System32\\drivers\\WdFilter.sys" ascii wide
		$defender_wdboot_driver = "%SystemRoot%\\System32\\drivers\\WdBoot.sys" ascii wide
		$defender_wdboot_driver_noenv = "C:\\Windows\\System32\\drivers\\WdBoot.sys" ascii wide
		$defender_net_stop_windefend = "net stop windefend" nocase ascii wide
		$defender_net_stop_SecurityHealthService = "net stop SecurityHealthService" nocase ascii wide
		$defender_powershell_exclusionpath = "Add-MpPreference -ExclusionPath" xor ascii wide
		$defender_powershell_exclusionpath_base64 = "Add-MpPreference -ExclusionPath" base64
		$defender_powershell_exclusionext = "Add-MpPreference -ExclusionExtension" ascii wide
		$defender_powershell_exclusionprocess = "Add-MpPreference -ExclusionProcess" ascii wide
		$defender_powershell_exclusionip = "Add-MpPreference -ExclusionIpAddress" ascii wide
		$defender_uilockdown = "Set-MpPreference -UILockdown" ascii wide
		$defender_uilockdown_force = "Set-MpPreference -Force -UILockdown" ascii wide
		$defender_securitycenter = "\\SOFTWARE\\Microsoft\\Windows Defender Security Center\\" ascii wide
		$defender_location = "C:\\Program Files (x86)\\Windows Defender\\" ascii wide
		$defender_clsid = "{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}" nocase ascii wide
		$defender_powershell_checksigsscan = "Set-MpPreference -CheckForSignaturesBeforeRunningScan" ascii wide
		$defender_powershell_noscanarchive = "Set-MpPreference -DisableArchiveScanning" ascii wide
		$defender_powershell_nobmon = "Set-MpPreference -DisableBehaviorMonitoring" ascii wide
		$defender_powershell_noemail = "Set-MpPreference -DisableEmailScanning" ascii wide
		$defender_powershell_ioav = "Set-MpPreference -DisableIOAVProtection" ascii wide
		$defender_powershell_privacymode = "Set-MpPreference -DisablePrivacyMode" ascii wide
		$defender_powershell_sigschday = "Set-MpPreference -SignatureScheduleDay" ascii wide
		$defender_powershell_noremovescan = "Set-MpPreference -DisableRemovableDriveScanning" ascii wide
		$defender_powershell_changewindefend = "Set-Service -Name windefend -StartupType " nocase ascii wide
		$defender_powershell_changesecurityhealth = "Set-Service -Name securityhealthservice -StartupType " nocase ascii wide
		$defender_protocol_key = "HKEY_CLASSES_ROOT\\windowsdefender" nocase ascii wide
		$defender_powershell_controlledfolder_replace = "Set-MpPreference -ControlledFolderAccessAllowedApplications" nocase ascii wide
		$defender_powershell_controlledfolder_replace_force = "Set-MpPreference -Force -ControlledFolderAccessAllowedApplications" nocase ascii wide
		$defender_powershell_controlledfolder_add = "Add-MpPreference -ControlledFolderAccessAllowedApplications" nocase ascii wide
		$defender_powershell_controlledfolder_add_force = "Add-MpPreference -Force -ControlledFolderAccessAllowedApplications" nocase ascii wide
		$defender_powershell_DisableScanningMappedNetworkDrivesForFullScan = "Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan" nocase ascii wide
		$defender_powershell_malwareid = "Add-MpPreference -ThreatIDDefaultAction_Ids " nocase ascii wide
		$defender_Windows_Security_Health_key = "\\SOFTWARE\\Microsoft\\Windows Security Health" nocase ascii wide
		$defender_service = "\\SYSTEM\\ControlSet001\\Services\\EventLog\\System\\WinDefend" nocase ascii wide
		$defender_sc_stop = "sc stop WinDefend" nocase ascii wide
		$defender_sc_delete = "sc delete WinDefend" nocase ascii wide
		$defender_sc_disable = "sc config WinDefend start= disabled" nocase ascii wide
		$defender_powershell_uninstall_feature = "Uninstall-WindowsFeature -Name Windows-Defender" nocase ascii wide
		$defender_service_key_WdNisDrv = "\\System\\CurrentControlSet\\Services\\WdNisDrv" nocase ascii wide
		$defender_service_key_WdNisSvc = "\\System\\CurrentControlSet\\Services\\WdNisSvc" nocase ascii wide
		$defender_service_key_WdBoot = "\\System\\CurrentControlSet\\Services\\Wdboot" nocase ascii wide
		$defender_securityandmaint_key = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Security and Maintenance" ascii wide
		$defender_task_1 = "schtasks /Change /TN \"Microsoft\\Windows\\ExploitGuard\\ExploitGuard MDM policy Refresh\"" ascii wide
		$defender_task_2 = "schtasks /Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Cache Maintenance\"" ascii wide
		$defender_task_3 = "schtasks /Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Cleanup\"" ascii wide
		$defender_task_4 = "schtasks /Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan\"" ascii wide
		$defender_task_5 = "schtasks /Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Verification\"" ascii wide nocase
		$defender_wmic = "WMIC /Namespace:\\\\root\\Microsoft\\Windows\\Defender" ascii wide nocase
		$defender_powershell_networkprotection = "Set-MpPreference -EnableNetworkProtection " ascii wide nocase
		$defender_restore_default = "\\MpCmdRun.exe -RestoreDefaults" ascii wide
		
		// Windows firewall
		$firewall_netsh_disable = "netsh advfirewall set allprofiles state off" ascii wide
		$firewall_reg_key = "\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\" ascii wide
		$firewall_sharedaccess_reg_key = "\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\" ascii wide
		$firewall_allow = "netsh firewall add allowedprogram" nocase ascii wide
		$firewall_changelogsize = "netsh advfirewall set currentprofile logging maxfilesize" ascii wide nocase
		
		// Microsoft Windows Malicious Software Removal Tool
		$MRT_reg_key = "\\SOFTWARE\\Policies\\Microsoft\\MRT" ascii wide
		$MRT_reg_key_wow64 = "\\SOFTWARE\\WOW6432NODE\\POLICIES\\MICROSOFT\\MRT" ascii wide
		$MRT_del = "del C:\\Windows\\System32\\mrt.exe" nocase ascii wide
		
		// Edge
		$edge_phishing_filter = "\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter" ascii wide
		
		// Internet Explorer
		$ie_phishing_filter = "\\SOFTWARE\\Microsoft\\Internet Explorer\\PhishingFilter" ascii wide
		
		// key, value pairs - these may have false positives
		$k1 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" ascii wide
		$k2 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
		$k3 = "\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" ascii wide
		$k4 = "\\SOFTWARE\\MICROSOFT\\SECURITY CENTER" nocase ascii wide
		
		$v1 = "HideSCAHealth" ascii wide
		$v2 = "SecurityHealth" ascii wide
		$v3 = "EnableSmartScreen" ascii wide
		$v4 = "FIREWALLDISABLENOTIFY" ascii wide nocase
		$v5 = "UPDATESDISABLENOTIFY" nocase ascii wide

	condition:
		any of ($defender_*) or any of ($firewall_*) or any of ($MRT_*) or any of ($edge_*) or any of ($ie_*) or (1 of ($k*) and 1 of ($v*))
}

rule disable_taskmgr
{
	meta:
		author = "iam-py-test"
		description = "Detect applications disabling task manager"
	strings:
		$pol_key = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii wide
		$pol_wow_key = "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii wide
		$value = "DISABLETASKMGR" nocase
	condition:
		any of ($pol*) and $value
}

rule hosts_file_blocks
{
	meta:
		author = "iam-py-test"
		description = "Detect files referencing HOSTs file entries to block security-software related websites"
	strings:
		$zs1 = "0.0.0.0       avast.com"
		$zs2 = "0.0.0.0       www.avast.com"
		$zs3 = "0.0.0.0       mcafee.com"
		$zs4 = "0.0.0.0       www.mcafee.com"
		$zs5 = "0.0.0.0       bitdefender.com"
		$zs6 = "0.0.0.0       www.bitdefender.com"
		$zs7 = "0.0.0.0       us.norton.com"
		$zs8 = "0.0.0.0       www.us.norton.com"
		$zs9 = "0.0.0.0       avg.com"
		$zs10 = "0.0.0.0       www.avg.com"
		$zs11 = "0.0.0.0       pandasecurity.com"
		$zs12 = "0.0.0.0       www.pandasecurity.com"
		$zs13 = "0.0.0.0       surfshark.com"
		$zs14 = "0.0.0.0       www.surfshark.com"
		$zs15 = "0.0.0.0       avira.com"
		$zs16 = "0.0.0.0       www.avira.com"
		$zs17 = "0.0.0.0       norton.com"
		$zs18 = "0.0.0.0       www.norton.com"
		$zs19 = "0.0.0.0       eset.com"
		$zs20 = "0.0.0.0       www.eset.com"
		$zs21 =  "0.0.0.0     novirusthanks.org"
		$zs22 = "0.0.0.0     www.novirusthanks.org"
		$zs23 = "0.0.0.0     virustotal.com"
		$zs24 = "0.0.0.0     www.virustotal.com"
		$zs25 = "0.0.0.0     virusscan.jotti.org"
		$zs26 = "0.0.0.0     www.virusscan.jotti.org"
		$zs27 = "0.0.0.0     malwarebytes.com"
		$zs28 = "0.0.0.0     www.malwarebytes.com"
		$zs29 = "0.0.0.0     bitdefender.com"
		$zs30 = "0.0.0.0     www.bitdefender.com"
		$zs31 = "0.0.0.0     eset.com"
		$zs32 = "0.0.0.0     www.eset.com"
		$zs33 = "0.0.0.0     trendmicro.com"
		$zs34 = "0.0.0.0     www.trendmicro.com"
		$zs35 = "0.0.0.0     kaspersky.com"
		$zs36 = "0.0.0.0     www.kaspersky.com"
		$zs37 = "0.0.0.0     f-secure.com"
		$zs38 = "0.0.0.0     www.f-secure.com"
		$zs39 = "0.0.0.0     avg.com"
		$zs40 = "0.0.0.0     www.avg.com"
		$zs41 = "0.0.0.0     avast.com"
		$zs42 = "0.0.0.0     www.avast.com"
		$zs43 = "0.0.0.0     avira.com"
		$zs44 = "0.0.0.0     www.avira.com"
		$zs45 = "0.0.0.0     zonealarm.com"
		$zs46 = "0.0.0.0     www.zonealarm.com"
		$zs47 = "0.0.0.0     pandasecurity.com"
		$zs48 = "0.0.0.0     www.pandasecurity.com"
		$zs49 = "0.0.0.0     aegislab.com"
		$zs50 = "0.0.0.0     www.aegislab.com"

	condition:
		3 of ($zs*)
}

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

rule Image_File_Exec_Options
{
	meta:
		author = "iam-py-test"
		description = "Detect files referencing Windows Image File Execution Options"
	strings:
		$wnt_ifeo = "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
		$wow6432_ifeo = "\\Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
	condition:
		any of them
}

rule internet_shortcut_to_file
{
	meta:
		author = "iam-py-test"
		date = "2022-11-21"
		description = ".url files can point to a file by specifying file:/// and then the path as the URL"
		// Yarahub
		yarahub_uuid = "70c7014d-66cb-410e-a376-37c53807282e"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
	strings:
		// detect if it is a .url file
		$is_urlfile_1 = "{000214A0-0000-0000-C000-000000000046}" // CLSID
		$is_urlfile_2 = "[InternetShortcut]"
		
		$file_url = "URL=file://" 
	condition:
		any of ($is_urlfile_*) and $file_url
}

rule JScriptCom
{
	meta:
		author = "iam-py-test"
		description = "Detect files referencing .Net jsc.exe (Microsoft JScript Compiler)"
		example_file = "ba85b8a6507b9f4272229af0606356bab42af42f5ee2633f23c5e149c3fb9ca4"
		in_the_wild = true
	strings:
		$filelocation = "C:\\Windows\\Microsoft.NET\\Framewor" ascii wide
		$applaunch = "\\jsc.exe" ascii wide
	condition:
		$filelocation and $applaunch
}

rule kill_explorer
{
	meta:
		author = "iam-py-test"
		description = "Detect files killing explorer.exe"
	strings:
		$malware_taskkill = "taskkill /F /IM explorer.exe" nocase
	condition:
		any of ($malware_*)
		
}

rule obf_wscript_shell
{
	meta:
		author = "iam-py-test"
		description = "Detect files trying to obfuscate or hide use of WScript.Shell"
	strings:
		$esc_hide = "W!S!c!r!i!p!t!.!S!h!e!l!l"
	condition:
		any of them
}

rule reference_odd_file_path
{
	meta:
		author = "iam-py-test"
		description = "Detect references to odd file paths"
	strings:
		$p1 = "\\AppData\\Roaming\\svchost.exe" ascii wide
		$p2 = "\\AppData\\Roaming\\sihost.exe" ascii wide
		$p3 = "\\Startup\\Microsoft Corporation.exe" nocase ascii wide
		$p4 = "\\ProgramData\\mzvgmp.bat" ascii wide
		$p5 = "\\SVCUPDATER.EXE" nocase ascii wide
		$p6 = "\\Windows\\Speech\\services.exe" ascii wide
		$p7 = "\\Windows\\Runtime Service.exe" ascii wide
		$p8 = "\\NETSVC4.EXE" nocase ascii wide
		$p9 = "\\AppData\\Local\\Updates\\Run.vbs" ascii wide
		$p10 = "\\Pictures\\SearchIndexer.exe" ascii wide
		$p11 = "\\svchostf.exe" ascii wide
		$p12 = "\\WindowsService.exe" ascii wide
		$p13 = "\\Music\\lsass.exe" ascii wide
		$p14 = "\\MicrosoftHost.exe" ascii wide
		$p15 = /\\Fonts\\[a-zA-Z0-9]*\.exe/
		$p16 = "\\H35c27gu.exe" ascii wide
		$p17 = "\\qEdJzM2d.exe" ascii wide nocase
		$p18 = "\\Y9QuxeJCZGmxxOGMOV2sEXu9.exe" ascii wide nocase
		
	condition:
		any of them
		
}

rule padded_with_zeros
{
	meta:
		author = "iam-py-test"
		description = "Detect executables which have large sections of zeros to increase their size"
	strings:
		$hex_mz = { 4D 5A }
		$zeros = { 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 }
	condition:
		// YARA says that this rule is problematic, as it matches too much
		$hex_mz at 0 and #zeros > 20 and filesize > 650MB
}

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

rule powershell_encoded_command
{
	meta:
		author = "iam-py-test"
		description = "Detect base64 encoded commands being sent to PowerShell"
	strings:
		$p1 = "powershell -WindowStyle Hidden -EncodedCommand " nocase ascii wide
		$p2 = "powershell -EncodedCommand " nocase ascii wide
		$p3 = "powershell.exe -EncodedCommand" nocase ascii wide
		$p4 = "powershell.exe -WindowStyle Hidden -EncodedCommand " nocase ascii wide
		$p5 = "powershell -enc " nocase ascii
		$p6 = "powershell.exe -enc" nocase ascii
	condition:
		any of them
}

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

rule ref_antivirus
{
	meta:
		author = "iam-py-test"
		description = "Detect files referencing files and directories used by security software"
	strings:
		$d1 = "C:\\Program Files\\Lavasoft" nocase ascii wide
		$d2 = "C:\\Program Files\\Mcafee" nocase ascii wide
		$d3 = "C:\\Program Files\\Trend Micro" nocase ascii wide
		$d4 = "C:\\Program Files\\kaspersky" nocase ascii wide
		$d5 = "C:\\Program Files\\Malwarebytes" nocase ascii wide
		$d6 = "C:\\Program Files (x86)\\Trend Micro" nocase ascii wide
		$d7 = "C:\\Program Files\\ESET\\ESET Security" nocase ascii wide
		$d8 = "C:\\Program Files\\Common Files\\McAfee" nocase ascii wide
		$d9 = "C:\\Program Files\\AVG"
		$d10 = "C:\\Program Files\\Avast Software"
	condition:
		3 of ($d*)
}

rule reversed_executable
{
	meta:
		author = "iam-py-test"
		description = "Detect Windows PEEXEs which have been reversed"
	strings:
		$reversed_dosmode = "edom SOD ni nur eb tonnac margorp sihT!"
		$reversed_magic = { 5A 4D }
	condition:
		$reversed_dosmode and $reversed_magic at (filesize - 2)
}

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

rule antivirus_service_stop
{
	meta:
		author = "iam-py-test"
		description = "Detect files stopping, disabling, or deleting services used by security software"
	strings:
		$mb1 = "get-service -displayname \"MBAMService\" | stop-service" nocase ascii wide
		$mb2 = "Get-Service -Name \"MBAMService\" | Stop-Service" nocase ascii wide
		$mb3 = "Get-Service MBAMService | Set-Service -StartupType Disabled"
	condition:
		any of them
}

rule vbc
{
	meta:
		author = "iam-py-test"
		description = "Detect files referencing .Net vbc.exe (Microsoft Visual Basic Compiler)"
		example_file = "24d5e7bf693f7390c33f2de7c1634c7973ca1b8d13cb7e7cf10c233250856473"
		in_the_wild = true
		date = "2022-11-21"
	strings:
		$filelocation = "C:\\Windows\\Microsoft.NET\\Framewor" ascii wide
		$vbc = "\\vbc.exe" ascii wide
	condition:
		$filelocation and $vbc
}

rule Malware_Breaking_Windows_Update
{
	meta:
		author = "iam-py-test"
		description = "Detect malware using cmd to disable or break Windows Update"
		example_file = "605086605298f8b99a3a847dda564e9abdb0a288059bbf9263a0e40e147b833e"
	strings:
		$stop_UsoSvc_service = "sc stop UsoSvc" 
		$stop_WaaSMedicSvc_service = "sc stop wuauserv" 
		$stop_bits_service = "sc stop bits" 
		$stop_dosvc_service = "sc stop dosvc" 
		$delete_service_key_UsoSvc = "reg delete HKLM\\SYSTEM\\CurrentControlSet\\Services\\UsoSvc /f"
		$delete_service_key_WaaSMedicSvc = "reg delete HKLM\\SYSTEM\\CurrentControlSet\\Services\\WaaSMedicSvc /f"
		$delete_service_key_wuauserv = "reg delete HKLM\\SYSTEM\\CurrentControlSet\\Services\\wuauserv /f"
		$delete_service_key_bits = "reg delete HKLM\\SYSTEM\\CurrentControlSet\\Services\\bits /f" 
		$delete_service_key_dosvc = "reg delete HKLM\\SYSTEM\\CurrentControlSet\\Services\\dosvc /f" 
		$delete_needed_file_takeown = "takeown /f %SystemRoot%\\System32\\WaaSMedicSvc.dll"
		$delete_needed_file_perm = "icacls %SystemRoot%\\System32\\WaaSMedicSvc.dll /grant"
		$delete_needed_file_change = /(del|rename|ren) %SystemRoot%\\System32\\WaaSMedicSvc.dll/
		$change_tasks_autoAppUpdate = "SCHTASKS /Change /TN \"\\Microsoft\\Windows\\WindowsUpdate\\Automatic App Update\" /DISABLE" 
		$change_tasks_schStart = "SCHTASKS /Change /TN \"\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start\" /DISABLE" 
		$change_tasks_sih = "SCHTASKS /Change /TN \"\\Microsoft\\Windows\\WindowsUpdate\\sih\" /DISABLE" 
		$change_tasks_sihboot = "SCHTASKS /Change /TN \"\\Microsoft\\Windows\\WindowsUpdate\\sihboot\" /DISABLE" 
		$change_tasks_UpdateAssistant = "SCHTASKS /Change /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\UpdateAssistant\" /DISABLE" 
		$change_tasks_UpdateAssistantCalendarRun = "SCHTASKS /Change /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\UpdateAssistantCalendarRun\" /DISABLE" 
		$change_tasks_UpdateAssistantWakeupRun = "SCHTASKS /Change /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\UpdateAssistantWakeupRun\" /DISABLE" 
	condition:
		((any of ($delete_service_key_*)) and (any of ($stop_*))) or ($delete_needed_file_takeown and $delete_needed_file_perm and $delete_needed_file_change) or (any of ($change_tasks_*))
}


rule Windows_Update_Restriction
{
	meta:
		author = "iam-py-test"
		description = "Detect files viewing/modifying restrictions on Windows Update"
	strings:
		$windows_update_policy_key = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
	condition:
		all of them
		
}


import "hash"
rule known_hash
{
	meta:
		author = "iam-py-test"
		description = "Detect files which I have analyzed before (to avoid duplicates)"
	condition:
		hash.sha256(0,filesize) == "fb82a2488abb19f293df06778ea6059413f9f08e198a096eb5142f3503f1781b" or hash.sha256(0,filesize) == "f82cf1d06e116945ecc0c995dd10c9e76e62ecbb9d7f0964d212822498d7c032" or hash.sha256(0,filesize) == "f9eba50e0208700ad9c1c3761a50c855f86439328fdfb888e5f3e5d4cb81e46b" 
}

rule betterjspop
{
	meta:
		author = "iam-py-test"
		description = "Detect code copied from https://github.com/nicxlau/BetterJsPop"
	strings:
		$s1 = "BetterJsPop.init" ascii wide
		$s2 = "BetterJsPop._getBrowserCapabilities" ascii wide
		$s3 = "e.popjsoriginalhref" ascii wide
		$s4 = "_openAd: function" ascii wide
		$s5 = "this.minipopmon" ascii wide
		$s6 = "this._openPopunderIE11" ascii wide
		$s7 = "function posred(){window.resizeTo(100,100);if (window.screenY>100)" ascii wide
		$s8 = "var BetterJsPop = {" ascii wide
	condition:
		3 of them
}

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

rule eicar_test_file
{
	meta:
		author = "iam-py-test"
		description = "Detect files containing the EICAR test file"
	strings:
		$e = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" nocase ascii wide
	condition:
		all of them
}

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

rule known_malware_29c7d7d36a0c8acec88ff7aa34adc0f9240270a85e330fd2336408e1f0d52c21
{
	meta:
		author = "iam-py-test"
		description = "Detect files similar to 29c7d7d36a0c8acec88ff7aa34adc0f9240270a85e330fd2336408e1f0d52c21"
		example = "29c7d7d36a0c8acec88ff7aa34adc0f9240270a85e330fd2336408e1f0d52c21"
	strings:
		$malware_sihost = "@sihost.exe"
		$malware_c2 = "45.155.165.151"
		$fp_sihost_in_system32 = "C:\\Windows\\System32\\sihost.exe"
		$fp_sihost_legit = ".text$lp01sihost.exe!35_hybridboot"
	condition:
		any of ($malware_*) and none of ($fp_*)
	
}

rule known_c2
{
	meta:
		author = "iam-py-test"
		description = "Detect files referencing known C2 servers"
	strings:
		$c2_1 = "116.202.5.101" // https://www.virustotal.com/gui/url/49799cb49d2c6a9696d3e911843b7098c52c274ec8fdbf25d0ba269e2b00a79a
		$c2_2 = "45.155.165.151" // https://www.virustotal.com/gui/file/29c7d7d36a0c8acec88ff7aa34adc0f9240270a85e330fd2336408e1f0d52c21
		$c2_3 = "88.198.106.9" // https://www.virustotal.com/gui/file/c695b3d55cafa00cfda4f4f50b42b6cd059d6db49184a48df22cfc9575a6d96c/detection 
		
		$fp_abpfilter = "[Adblock Plus 2.0]"
	condition:
		any of ($c2_*) and none of ($fp_*)
}

rule Nimbo_C2
{
	meta:
		author = "iam-py-test"
		description = "Detect https://github.com/itaymigdal/Nimbo-C2"
	strings:
		// nimbo-specific strings
		$n1 = "github.com/itaymigdal/Nimbo-C2"
		$n2 = "Lightweight C2 Framework for villains" nocase
		$n3 = "By Itay Migdal" nocase
		$n4 = "exit Nimbo-C2" nocase
		$n5 = "Nimbo-C2 w1ll r0ck y0ur w0rld :)"
		
		// strings in the Python file
		$p1 = "def exit_nimbo"
		$p2 = "patch_stdout"
		$p3 = "print_agents("
		$p4 = "listener.agents.pop(agent_id)"
		
	condition:
		any of ($n*) or 2 of ($p*)
}

rule processhacker
{
	meta:
		author = "iam-py-test"
		description = "Process Hacker is a open source tool for Windows. While this tool is benign, it is sometimes abused"
		date = "2022-11-21"
	strings:
		// the main process hacker file
		$ph1 = "Process Hacker"
		$ph2 = "\\x86\\ProcessHacker.exe"
		$ph3 = "\\Release32\\ProcessHacker.exe"
		$ph4 = "KProcessHacker"
		$ph5 = "A_ProcessHacker"
		$ph6 = "Hidden Processes.txt"
		$ph7 = "ProcessHacker.exe"
		$ph8 = "ProcessHacker.sig"
		$ph9 = "\\BaseNamedObjects\\ProcessHacker2Mutant"
		$ph10 = "sourceforge.net/project/project_donations.php?group_id=242527"
		
		// kprocesshacker driver
		$kph1 = "d:\\projects\\processhacker2\\kprocesshacker\\bin\\amd64\\kprocesshacker.pdb"
		$kph2 = "kprocesshacker.sys"
	condition:
		2 of ($ph*) or any of ($kph*)
}

rule iexplorer_remcos
{
	meta:
		author = "iam-py-test"
		description = "Detect iexplorer being taken over by Remcos"
	strings:
		$ie1 = "C:\\Program Files(x86)\\Internet Explorer" ascii wide
		$ie2 = "ieinstal.exe" ascii wide
		$ie3 = "ielowutil.exe" ascii wide
		
		$r1 = "Remcos Agent initialized"
		$r2 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f" ascii wide
		$r3 = "Remcos restarted by watchdog!" ascii wide
		$r4 = "Watchdog module activated" ascii wide
		$r5 = "Watchdog launch failed!" ascii wide
		$r6 = "BreakingSecurity.net" ascii wide
	condition:
		2 of ($ie*) and any of ($r*)
}

