rule conficker
{
    meta:
        description = "Detects Conficker malware"
        author = "Franklin Charity"
    
    strings:
        $a = { 60 63 6F 6E 66 69 67 75 } // "<configu"
        $b = { 4D 5A } // "MZ"
        $c = { 68 ?? ?? ?? ?? 8D 45 ?? 50 B8 ?? ?? ?? ?? E8 } // "h...P......."
        $d = { E8 ?? ?? ?? ?? 33 C0 50 50 50 50 40 50 48 33 C0 48 50 FF 15 ?? ?? ?? ?? 83 C4 20 5E } // ".......PPPPP@P3.P^"
    
    condition:
        $a and $b and $c and $d
}
