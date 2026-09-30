#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\AJNAT",
    [string]$DataDir = "$env:ProgramData\AJNAT",
    [string]$ServiceName = "SOCAgent",
    [string]$ResultPath = ""
)

$ErrorActionPreference = 'Stop'
$expectedInstallDir = [System.IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'AJNAT')).TrimEnd('\')
$expectedDataDir = [System.IO.Path]::GetFullPath((Join-Path $env:ProgramData 'AJNAT')).TrimEnd('\')
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
$DataDir = [System.IO.Path]::GetFullPath($DataDir).TrimEnd('\')
if ($InstallDir -ne $expectedInstallDir -or $DataDir -ne $expectedDataDir) {
    throw "Refusing to repair unexpected paths: install=$InstallDir data=$DataDir"
}
if (-not (Test-Path -LiteralPath "$InstallDir\agent.py")) {
    throw "AJNAT agent.py was not found in $InstallDir"
}

function Invoke-CheckedNative {
    param([string]$FilePath, [string[]]$Arguments, [string]$Description)
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $FilePath @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedPreference
    }
    if ($code -ne 0) {
        throw ("{0} failed with exit code {1}: {2}" -f $Description, $code, ($output -join ' '))
    }
}

function Repair-AgentTree {
    param([string]$Path, [switch]$AllowUsersRead)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Invoke-CheckedNative takeown.exe @('/F', $Path, '/A', '/R', '/D', 'Y') "Take ownership of $Path"
    Invoke-CheckedNative icacls.exe @($Path, '/reset', '/T', '/C', '/Q') "Reset ACLs on $Path"
    $rules = @($Path, '/inheritance:e', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
    if ($AllowUsersRead) { $rules += '*S-1-5-32-545:(OI)(CI)RX' }
    $rules += @('/T', '/C', '/Q')
    Invoke-CheckedNative icacls.exe $rules "Grant installer access on $Path"
    $directRules = @($Path, '/grant', '*S-1-5-18:F', '*S-1-5-32-544:F')
    if ($AllowUsersRead) { $directRules += '*S-1-5-32-545:RX' }
    $directRules += @('/T', '/C', '/Q')
    Invoke-CheckedNative icacls.exe $directRules "Grant direct access to existing files in $Path"
}

$result = [ordered]@{
    timestamp = (Get-Date -Format o)
    repaired = $false
    service = 'unknown'
    healthExitCode = $null
    message = ''
}

try {
    Repair-AgentTree -Path $InstallDir -AllowUsersRead
    Repair-AgentTree -Path $DataDir

    $logDir = Join-Path $DataDir 'logs'
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    Invoke-CheckedNative icacls.exe @($DataDir, '/grant:r', '*S-1-5-32-545:RX', '/Q') 'Grant runtime traversal access'
    Invoke-CheckedNative icacls.exe @($logDir, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-32-545:(OI)(CI)RX', '/T', '/C', '/Q') 'Grant diagnostic log read access'
    Invoke-CheckedNative icacls.exe @($logDir, '/grant', '*S-1-5-18:F', '*S-1-5-32-544:F', '*S-1-5-32-545:RX', '/T', '/C', '/Q') 'Grant direct diagnostic log read access'

    $service = Get-Service -Name $ServiceName -ErrorAction Stop
    if ($service.Status -ne 'Running') {
        Start-Service -Name $ServiceName -ErrorAction Stop
        $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    }

    $pythonPath = @(
        "$env:ProgramFiles\Python313\python.exe",
        "$env:ProgramFiles\Python312\python.exe"
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $pythonPath) { throw 'Supported system Python was not found' }

    $env:AJNAT_DATA_DIR = $DataDir
    $env:SOC_AGENT_CONFIG = Join-Path $DataDir 'config\company_config.json'
    $env:PYTHONUTF8 = '1'
    $env:PYTHONIOENCODING = 'utf-8'
    & $pythonPath "$InstallDir\agent.py" test
    $result.healthExitCode = $LASTEXITCODE
    if ($LASTEXITCODE -ne 0) { throw "Agent health check failed with exit code $LASTEXITCODE" }

    Start-Sleep -Seconds 5
    $service = Get-Service -Name $ServiceName -ErrorAction Stop
    if ($service.Status -ne 'Running') { throw 'SOCAgent exited during the stability check' }

    $result.repaired = $true
    $result.service = (Get-Service -Name $ServiceName -ErrorAction Stop).Status.ToString()
    $result.message = 'ACL repair, service start, and agent health check succeeded.'
} catch {
    $result.message = $_.Exception.Message
    try { $result.service = (Get-Service -Name $ServiceName -ErrorAction Stop).Status.ToString() } catch { $result.service = 'missing' }
    throw
} finally {
    if ($ResultPath) {
        $result | ConvertTo-Json | Set-Content -LiteralPath $ResultPath -Encoding UTF8
    }
}

$result | ConvertTo-Json
