rule Bladabindi_njRAT_Spying_C2 {
    meta:
        description = "Detects Keylogging and a C2 domain"
        author = "Aitor"
        date = "2026-03-19"

    strings:
        $api_key1 = "GetAsyncKeyState" ascii wide
        $api_key2 = "GetForegroundWindow" ascii wide
        $c2_domain = "soa7.zapto.org" ascii wide
        $run_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide

    condition:
        uint16(0) == 0x5A4D and 
        ($c2_domain and 2 of ($api_key*, $run_key))
}
