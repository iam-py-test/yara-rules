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