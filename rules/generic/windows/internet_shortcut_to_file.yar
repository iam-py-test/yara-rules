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