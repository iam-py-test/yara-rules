rule internet_shortcut_to_file
{
	meta:
		author = "iam-py-test"
		date = "2022-11-21"
		description = ".url files can point to a file by specifying file:/// and then the path as the URL"
	strings:
		// detect if it is a .url file
		$is_urlfile_1 = "{000214A0-0000-0000-C000-000000000046}" // CLSID
		$is_urlfile_2 = "[InternetShortcut]"
		
		$file_url = "URL=file://" 
	condition:
		any of ($is_urlfile_*) and $file_url
}