rule Yara_Example {
    
    meta: 
        last_updated = "2024-02-25"
        author = "Siddharth Johri"
        description = "A sample Yara rule for identifying a binary(Malware.yara1.exe.malz)"

    strings:
        // Fill out identifying strings and other criteria
        $string1 = "YOURETHEMANNOWDOG" ascii
        $string2 = "nim"
        $PE_magic_byte = "MZ"
        $sus_hex_string = { FF E4 ?? 00 FF }

    condition:
        // Fill out the conditions that must be met to identify the binary
        $PE_magic_byte at 0 and 
        ($string1 and $string2) or
        $sus_hex_string
}
