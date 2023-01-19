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