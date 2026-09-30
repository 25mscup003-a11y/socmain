rule WebShell {
    meta: description = "Web shell"
    strings:
        $a = "eval(base64_decode" nocase
        $b = "system($_GET" nocase
    condition: any of them
}
rule Keylogger {
    meta: description = "Keylogger indicators"
    strings:
        $a = "GetAsyncKeyState" nocase
        $b = "SetWindowsHookEx" nocase
    condition: any of them
}
