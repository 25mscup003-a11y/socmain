# Run in an elevated PowerShell/Pester session on the Windows test machine.
# This verifies the installed result without printing configuration or secrets.
param(
    [string]$ServiceName = "SOCAgent",
    [string]$InstallDir = "$env:ProgramFiles\AJNAT",
    [string]$DataDir = "$env:ProgramData\AJNAT"
)

Describe "AJNAT Windows service installation" {
    It "installs the resolved service and reaches Running" {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        $service.Status | Should -Be "Running"
    }

    It "uses delayed automatic startup" {
        $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
        $service.StartMode | Should -Be "Auto"
        (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName").DelayedAutoStart | Should -Be 1
    }

    It "has the required service entry point and protected configuration" {
        Test-Path "$InstallDir\windows_service.py" | Should -BeTrue
        Test-Path "$InstallDir\agent.py" | Should -BeTrue
        Test-Path "$DataDir\config\company_config.json" | Should -BeTrue
    }

    It "creates service and agent runtime logs" {
        Test-Path "$DataDir\logs\service-install.log" | Should -BeTrue
        Test-Path "$DataDir\logs\agent.log" | Should -BeTrue
    }

    It "stops and starts cleanly" {
        Stop-Service -Name $ServiceName -ErrorAction Stop
        (Get-Service -Name $ServiceName).WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
        Start-Service -Name $ServiceName -ErrorAction Stop
        (Get-Service -Name $ServiceName).WaitForStatus("Running", [TimeSpan]::FromSeconds(30))
        (Get-Service -Name $ServiceName).Status | Should -Be "Running"
    }

    It "does not grant normal Users write access to application binaries" {
        $acl = Get-Acl $InstallDir
        $writeRules = $acl.Access | Where-Object {
            $_.AccessControlType -eq "Allow" -and
            $_.IdentityReference -match "Users|Everyone|Authenticated Users" -and
            ($_.FileSystemRights.ToString() -match "Write|Modify|FullControl")
        }
        $writeRules | Should -BeNullOrEmpty
    }
}
