/*
 * Metasploit/Meterpreter memory indicators for validating MemNixFS YARA scans.
 * Generic reverse-shell hits are supporting evidence, not proof of compromise.
 */

rule MemNixFS_Meterpreter_Distinctive_Strings
{
    meta:
        description = "Distinctive Meterpreter runtime and extension strings"
        confidence = "high"
    strings:
        $metsrv          = "metsrv" ascii wide nocase
        $stdapi          = "stdapi_" ascii wide
        $priv            = "priv_" ascii wide
        $meterpreter     = "meterpreter" ascii wide nocase
        $reflective      = "ReflectiveLoader" ascii wide
        $core_loadlib    = "core_loadlib" ascii wide
        $core_channel    = "core_channel_" ascii wide
    condition:
        $meterpreter or $reflective or
        ($metsrv and 1 of ($stdapi, $priv, $core_loadlib, $core_channel))
}

rule MemNixFS_Metasploit_Transport_Artifacts
{
    meta:
        description = "Metasploit reverse transport and staging artifacts"
        confidence = "medium"
    strings:
        $uri_checksum    = "INITM" ascii
        $reverse_tcp     = "reverse_tcp" ascii wide nocase
        $reverse_http    = "reverse_http" ascii wide nocase
        $reverse_https   = "reverse_https" ascii wide nocase
        $payload_uuid    = "payload_uuid" ascii wide nocase
        $metasploit      = "Metasploit" ascii wide nocase
    condition:
        2 of them
}

rule MemNixFS_Linux_Reverse_Shell_Indicators
{
    meta:
        description = "Generic Linux reverse-shell command combinations"
        confidence = "low"
    strings:
        $devtcp          = "/dev/tcp/" ascii
        $bash_i          = "bash -i" ascii
        $sh_c            = "/bin/sh -c" ascii
        $python_socket   = "socket.socket(" ascii
        $dup2            = "dup2(" ascii
        $nc_exec         = "nc -e " ascii nocase
        $socat_exec      = "socat " ascii nocase
    condition:
        any of ($nc_exec, $socat_exec) or
        ($devtcp and $bash_i) or
        ($python_socket and $dup2) or
        ($sh_c and 1 of ($devtcp, $nc_exec, $socat_exec))
}
