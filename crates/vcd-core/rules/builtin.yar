/*
 * Rules compiled into Virus Check Desktop.
 *
 * Keep this file small and defensible: every entry here runs on every scan, so
 * a noisy rule costs accuracy for everyone. Anything broader belongs in the
 * user rules directory (%LOCALAPPDATA%\VirusCheckDesktop\rules).
 */

rule eicar_test_file : test antivirus
{
    meta:
        description = "EICAR antivirus test file (harmless, standard industry test string)"
        severity = "malicious"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule powershell_encoded_command : powershell script
{
    meta:
        description = "PowerShell invoked with an encoded command (common loader pattern; admins also do this, so it stays suspicious)"
        severity = "suspicious"
    strings:
        $encoded = /-[Ee]nc(odedCommand)?[ \t]+[A-Za-z0-9+\/]{24,}={0,2}/
    condition:
        $encoded
}
