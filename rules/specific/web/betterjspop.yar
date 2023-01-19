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