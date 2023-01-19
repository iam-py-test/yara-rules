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