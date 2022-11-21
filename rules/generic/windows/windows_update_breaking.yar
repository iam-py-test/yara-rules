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
