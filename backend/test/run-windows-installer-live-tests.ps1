#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ArtifactsDir,
    [Parameter(Mandatory)]
    [string]$TestConfigPath,
    [string]$ResultPath = ""
)

$ErrorActionPreference = 'Stop'
$installDir = Join-Path $env:ProgramFiles 'AJNAT'
$dataDir = Join-Path $env:ProgramData 'AJNAT'
$configPath = Join-Path $dataDir 'config\company_config.json'
$backupDir = Join-Path $env:TEMP ("AJNAT-installer-live-test-" + [guid]::NewGuid().ToString('N'))
$pythonPath = @(
    (Join-Path $env:ProgramFiles 'Python313\python.exe'),
    (Join-Path $env:ProgramFiles 'Python312\python.exe')
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

if (-not $pythonPath) { throw 'Supported system Python was not found' }
if (-not (Test-Path -LiteralPath $TestConfigPath)) { throw 'Live-test config was not found' }

$results = [ordered]@{
    timestamp = (Get-Date -Format o)
    preflightHealthExitCode = $null
    exe = $null
    msi = $null
    restoredProductionConfig = $false
}

function Grant-AdminAccess([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    & takeown.exe /F $Path /A | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "takeown failed for $Path" }
    & icacls.exe $Path /grant '*S-1-5-32-544:F' /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed for $Path" }
}

function Assert-LiveAgent([string]$Kind, [int]$InstallerExitCode) {
    $service = Get-Service -Name 'SOCAgent' -ErrorAction Stop
    if ($service.Status -ne 'Running') {
        $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    }

    $env:AJNAT_DATA_DIR = $dataDir
    $env:SOC_AGENT_CONFIG = $configPath
    $env:PYTHONUTF8 = '1'
    $env:PYTHONIOENCODING = 'utf-8'
    & $pythonPath (Join-Path $installDir 'agent.py') test | Out-Null
    $healthExitCode = $LASTEXITCODE
    if ($healthExitCode -ne 0) { throw "$Kind agent health check failed with exit code $healthExitCode" }

    Start-Sleep -Seconds 6
    $service = Get-Service -Name 'SOCAgent' -ErrorAction Stop
    if ($service.Status -ne 'Running') { throw "$Kind service did not remain Running" }
    $agentChildren = @(Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
        Where-Object { $_.CommandLine -match '(?i)AJNAT\\agent\.py"?\s+run' })
    if ($agentChildren.Count -lt 1) { throw "$Kind service has no live agent.py child process" }
    $agentLog = Join-Path $dataDir 'logs\agent.log'
    if (-not (Test-Path -LiteralPath $agentLog)) { throw "$Kind did not create agent.log" }
    $runningMarker = Select-String -LiteralPath $agentLog -Pattern 'SOC Agent running' -SimpleMatch -Quiet
    if (-not $runningMarker) { throw "$Kind agent never reached its monitoring loop" }

    return [ordered]@{
        installerExitCode = $InstallerExitCode
        service = $service.Status.ToString()
        childProcesses = $agentChildren.Count
        healthExitCode = $healthExitCode
        monitoringLoop = $runningMarker
    }
}

try {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    if (Test-Path -LiteralPath $configPath) {
        Grant-AdminAccess -Path $configPath
        Copy-Item -LiteralPath $configPath -Destination (Join-Path $backupDir 'company_config.json') -Force
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $configPath) -Force | Out-Null
    Grant-AdminAccess -Path $configPath
    Copy-Item -LiteralPath $TestConfigPath -Destination $configPath -Force

    $sourceAgent = Join-Path (Split-Path -Parent $PSScriptRoot) 'soc-agent\agent.py'
    & $pythonPath $sourceAgent test --config $configPath | Out-Null
    $results.preflightHealthExitCode = $LASTEXITCODE
    if ($LASTEXITCODE -ne 0) { throw "Preflight agent health check failed with exit code $LASTEXITCODE" }

    $exePath = Join-Path $ArtifactsDir 'ajnat-agent-windows.exe'
    $exe = Start-Process -FilePath $exePath -ArgumentList '/S' -Wait -PassThru -WindowStyle Hidden
    if ($exe.ExitCode -ne 0) { throw "EXE installer failed with exit code $($exe.ExitCode)" }
    $results.exe = Assert-LiveAgent -Kind 'EXE' -InstallerExitCode $exe.ExitCode

    $msiPath = Join-Path $ArtifactsDir 'ajnat-agent-windows.msi'
    $msiLog = Join-Path $ArtifactsDir 'msi-live-install.log'
    $msiArgs = @('/i', $msiPath, '/qn', '/norestart', '/L*v', $msiLog)
    $msi = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru -WindowStyle Hidden
    if ($msi.ExitCode -ne 0) { throw "MSI installer failed with exit code $($msi.ExitCode); see $msiLog" }
    $results.msi = Assert-LiveAgent -Kind 'MSI' -InstallerExitCode $msi.ExitCode
} finally {
    $savedConfig = Join-Path $backupDir 'company_config.json'
    if (Test-Path -LiteralPath $savedConfig) {
        Stop-Service -Name 'SOCAgent' -Force -ErrorAction SilentlyContinue
        Grant-AdminAccess -Path $configPath
        Copy-Item -LiteralPath $savedConfig -Destination $configPath -Force
        Start-Service -Name 'SOCAgent' -ErrorAction SilentlyContinue
        $results.restoredProductionConfig = $true
    }
    Remove-Item -LiteralPath $backupDir -Recurse -Force -ErrorAction SilentlyContinue
    if ($ResultPath) {
        $results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
    }
}

$results | ConvertTo-Json -Depth 4
