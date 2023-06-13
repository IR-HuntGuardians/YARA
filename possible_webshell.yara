rule possible_UnrealisticGazelle_webshell
{
	meta:

		author = "Threat Analysis And Research (TAR) Team"
		description = "This rule is for a malicous uploader on .NET webservers and is only for hunting and it's not tested against a large database, so it may produce some False Positives (FPs)."
		category = "Gazelle WebShell used for hack and leak operations"
		tlp = "White"

	strings:

		$pagelanguage = "<%@ Page Language=\"C#\""

		$s0 = { 70 54 37 35 67 23 58 35 23 6c 69 6a }	

		$s1 = { 52 65 71 75 65 73 74 2e 50 61 72 61 6d 73 5b [1-24] 5d }

		$s2 = { 66 69 6c 65 53 74 72 65 61 6d 2e 57 72 69 74 65 }

		$t1 = { 3c 66 6f 72 6d 20 65 6e 63 74 79 70 65 3d 5c 22 6d 75 6c 74 69 70 61 72 74 2f 66 6f 72 6d 2d 64 61 74 61 5c 22 20 61 63 74 69 6f 6e 3d 5c 22 3f 6f 70 65 72 61 74 69 6f 6e 3d 75 70 6c 6f 61 64 5c }

		$t2 = { 3c 62 72 3e 41 75 74 68 3a 20 3c 69 6e 70 75 74 20 74 79 70 65 3d 5c 22 74 65 78 74 5c 22 20 6e 61 6d 65 3d 5c 22 61 75 74 68 4b 65 79 5c 22 3e 3c 62 72 3e }

		$t3 = { 3c 62 72 3e 66 69 6c 65 3a 20 3c 69 6e 70 75 74 20 74 79 70 65 3d 5c 22 66 69 6c 65 5c 22 20 6e 61 6d 65 3d 5c 22 66 69 6c 65 5c 22 3e 3c 2f 62 72 3e }

	condition:
		filesize < 30KB and (($pagelanguage and $s0) or ($s1 and $s2 and 1 of ($t*)))
}