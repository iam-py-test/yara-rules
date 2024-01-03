rule python_botnet_01
{
	meta:
		description = "Detect hxxpx[://]github[.]com/MalwareMakers/Python-Botnet/blob/main/Harbringer.py"
	strings:
		$s1 = "Define function to handle keystrokeshelo"
		$s2 = "\"username\": \"Keylogger\","
		$s3 = "IP_API Info Grabber"
		$s4 = "hunt_upload"
		$s5 = "Self-deletion successful. The file '{script_path}' has been deleted."
		$s6 = "value_name = \"WindowsSecurity\""
}