import "hash"

rule KozaliBear_bitcoin{
    meta:
        description = "KozaliBear Ransomware attack"
        author = "csd4616"
        date = "19-4-2024"
    strings:
        $bitcoin="bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6"
    condition:
        $bitcoin
}

rule KozaliBear_signature{
    meta:
        description = "KozaliBear Ransomware attack"
        author = "csd4616"
        date = "19-4-2024"
    strings:
        $sig = { 98 1D 00 00 EC 33 FF FF FB 06 00 00 00 46 0E 10 }
    condition:
        $sig
}

rule KozaliBear_Malware_Website{
    meta:
        description = "KozaliBear Ransomware attack"
        author = "csd4616"
        date = "19-4-2024"
    strings:
        $web = "www.alphaxiom.com"
    condition:
        $web
}

rule KozaliBear_sha256{        
    meta:
        description = "KozaliBear Ransomware attack"
        author = "csd4616"
        date = "19-4-2024"
    condition:
        (hash.sha256(0,filesize) == "d56d67f2c43411d966525b3250bfaa1a85db34bf371468df1b6a9882fee78849")
}

rule KozaliBear_md5{           
    meta:
        description = "KozaliBear Ransomware attack"
        author = "csd4616"
        date = "19-4-2024"
    condition:
        (hash.md5(0,filesize) == "85578cd4404c6d586cd0ae1b36c98aca")
}
