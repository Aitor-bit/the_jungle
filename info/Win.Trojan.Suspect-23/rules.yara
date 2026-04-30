rule malware_jigsaw {
    meta:
        description = "Detects IoCs from the password.txt.exe file"
        author = "Aitor"
        date = "2026-04-27"

    strings:
        // Github connection
        $url_github = "https://raw.githubusercontent.com/junquera/MUCS-UAH-REM-PEF-2019"
        
        // Steganography
        $dll_color = "mscms.dll" ascii wide
        $func_color = "OpenColorProfileW"
        
        // Some weird files
        $file_ransom = "ransom.txt" ascii wide
        $file_result = "resultado.jpg" ascii wide
        $file_jigsaw = "Jigsaw.jpg" ascii wide

    condition:
        // Must be a Windows PE
        uint16(0) == 0x5A4D and 
        
        ($url_github and 2 of ($dll_color, $func_color, $file_ransom, $file_result, $file_jigsaw))
}
