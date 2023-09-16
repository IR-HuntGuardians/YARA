import "pe"

rule possible_Packed_JackalControl
{
	meta:
		author = "Threat Hunting (TH) Team"
		description = "This rule detects backdoor(s) written in .NET by GoldenJackal TA; It's only for hunting and because of that reason we didn't tested it against a large database, so it may produce some False Positives (FPs)."
		category = "GoldenJackal Backdoor (JackalControl) used in attacks against Iran(ian) government and diplomatic entities" 
		tlp = "Green"

	strings:
	
		$base64decode = { 28 [4] 0B 73 [4] 0C 08 72 [4] 04 1F 7C 8C [4] 07 }

		$runkey = { 28 [4] 28 [4] ?? 7E [4] 72 [4] 17 6F [4] 02 }

		$victimID = { 11 05 28 [4] 6F [4] 13 ?? 28 [4] 13 ?? 11 }

		$systemproduct = { 72 [4] 73 [4] 28 [4] 0B 07 6F [4] 13 }

		$desprovider = { 73 [4] 0B 73 [4] 0C }

		$doctype = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">" ascii wide nocase

		$debugdata = "<!-- DEBUGDATA::" ascii wide nocase

	condition:
		uint16(0) == 0x5a4d 		and
		uint32(uint32(0x3C)) == 0x4550 and
		pe.imports("mscoree.dll")	and
		($doctype and $debugdata) or
		($base64decode and $runkey and $victimID and $systemproduct and $desprovider)
}