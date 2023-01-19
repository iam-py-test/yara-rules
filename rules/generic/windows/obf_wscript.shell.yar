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