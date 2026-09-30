rule WannaCryIndicator {
    meta: description = "WannaCry ransomware indicator"
    strings:
        $a = "WannaDecryptor" nocase
        $b = ".wncry" nocase
    condition: any of them
}
rule RansomNote {
    meta: description = "Ransomware ransom note"
    strings:
        $a = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $b = "HOW_TO_DECRYPT" nocase
    condition: any of them
}
rule ShadowCopyDeletion {
    meta: description = "Shadow copy deletion"
    strings:
        $a = "vssadmin delete shadows" nocase
        $b = "wmic shadowcopy delete" nocase
    condition: any of them
}
