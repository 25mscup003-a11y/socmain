#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
Safely updates an existing AJNAT SOC Agent from a signed MSI or EXE package.

.EXAMPLE
PowerShell.exe -ExecutionPolicy Bypass -File .\update-installed-agent-windows.ps1 `
  -PackagePath .\soc-agent_v0.1.10_windows.msi

.EXAMPLE
PowerShell.exe -ExecutionPolicy Bypass -File .\update-installed-agent-windows.ps1 `
  -PackagePath .\soc-agent_v0.1.10_windows.exe

.EXAMPLE
# Use this only for the AJNAT local-test certificate supplied with the MSI.
PowerShell.exe -ExecutionPolicy Bypass -File .\update-installed-agent-windows.ps1 `
  -PackagePath .\soc-agent_v0.1.10_windows.msi `
  -CertificatePath .\AJNAT-Local-Test-Publisher.cer `
  -TrustLocalTestPublisher

.NOTES
Run from an elevated PowerShell window. This script does not weaken or bypass
Windows Defender Application Control (WDAC). A centrally managed WDAC policy
must explicitly allow the AJNAT publisher when publisher trust alone is not
sufficient.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$PackagePath,

    [string]$CertificatePath = (Join-Path $PSScriptRoot 'AJNAT-Local-Test-Publisher.cer'),

    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$ExpectedSha256,

    [switch]$TrustLocalTestPublisher,

    [string]$ServiceName = 'SOCAgent'
)

$ErrorActionPreference = 'Stop'
$PackagePath = (Resolve-Path -LiteralPath $PackagePath).Path
$extension = [IO.Path]::GetExtension($PackagePath).ToLowerInvariant()
if ($extension -notin @('.msi', '.exe')) {
    throw 'Only a signed AJNAT Windows MSI or EXE update package is accepted.'
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $service) {
    throw "Installed AJNAT service '$ServiceName' was not found. Use the normal installer for a fresh installation."
}

$dataDir = Join-Path $env:ProgramData 'AJNAT'
$logDir = Join-Path $dataDir 'logs'
$configCandidates = @(
    (Join-Path $dataDir 'config\company_config.json'),
    (Join-Path $env:ProgramFiles 'AJNAT\config\company_config.json')
)
$configPath = $configCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $configPath) {
    throw 'The existing AJNAT enrollment config was not found; refusing an update that could create a duplicate agent.'
}

$installDir = Join-Path $env:ProgramFiles 'AJNAT'
$pythonCandidates = @(
    (Join-Path $installDir 'runtime\python\python.exe'),
    (Join-Path $env:ProgramFiles 'Python313\python.exe'),
    (Join-Path $env:ProgramFiles 'Python312\python.exe')
)
$programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
if ($programFilesX86) {
    $pythonCandidates += (Join-Path $programFilesX86 'Python313\python.exe')
    $pythonCandidates += (Join-Path $programFilesX86 'Python312\python.exe')
}
$python = $pythonCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
function Read-AjnatConfig([string]$Path) {
    try { return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json) } catch {}
    if (-not $python) { throw 'Python is required to decrypt the installed AJNAT config.' }
    $json = & $python -c "import json,sys; sys.path.insert(0,sys.argv[1]); from core.config_protection import load_config; print(json.dumps(load_config(sys.argv[2])))" $installDir $Path
    if ($LASTEXITCODE -ne 0) { throw "Could not decrypt AJNAT enrollment config: $Path" }
    return ($json | ConvertFrom-Json)
}

$existingConfig = Read-AjnatConfig $configPath
$existingAgentKey = [string]$existingConfig.agent_key
$existingSystemId = [string]$existingConfig.system_id
if (-not $existingAgentKey -or -not $existingSystemId) {
    throw "The installed enrollment config is incomplete: $configPath"
}

New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$installerLog = Join-Path $logDir "manual-update-$stamp.log"
$otaLog = Join-Path $logDir 'ota-update.log'
$otaLineCount = if (Test-Path -LiteralPath $otaLog) { @(Get-Content -LiteralPath $otaLog).Count } else { 0 }

$actualSha256 = (Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256).Hash.ToUpperInvariant()
if ($ExpectedSha256 -and $actualSha256 -ne $ExpectedSha256.ToUpperInvariant()) {
    throw "Package SHA-256 mismatch. Expected $($ExpectedSha256.ToUpperInvariant()), received $actualSha256"
}

$signature = Get-AuthenticodeSignature -LiteralPath $PackagePath
if (-not $signature.SignerCertificate -or $signature.Status -in @('NotSigned', 'HashMismatch')) {
    throw "The update package has no usable Authenticode signature (status: $($signature.Status)). Update cancelled."
}

if ($TrustLocalTestPublisher) {
    if (-not (Test-Path -LiteralPath $CertificatePath -PathType Leaf)) {
        throw "AJNAT publisher certificate not found: $CertificatePath"
    }

    $publisher = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $CertificatePath
    try {
        if ($publisher.NotBefore -gt (Get-Date) -or $publisher.NotAfter -lt (Get-Date)) {
            throw 'The AJNAT publisher certificate is not currently valid.'
        }
        if ($publisher.Thumbprint -ne $signature.SignerCertificate.Thumbprint) {
            throw "Publisher mismatch: the certificate does not match the package signer. Certificate=$($publisher.Thumbprint), Package=$($signature.SignerCertificate.Thumbprint)"
        }

        foreach ($storeName in @('Root', 'TrustedPublisher')) {
            $store = New-Object Security.Cryptography.X509Certificates.X509Store($storeName, 'LocalMachine')
            try {
                $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $present = @($store.Certificates | Where-Object { $_.Thumbprint -eq $publisher.Thumbprint }).Count -gt 0
                if (-not $present) {
                    $store.Add($publisher)
                }
            } finally {
                $store.Close()
            }
        }
    } finally {
        $publisher.Dispose()
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $PackagePath
}

if ($signature.Status -ne 'Valid') {
    $hint = if ($TrustLocalTestPublisher) {
        'The signer is trusted locally but Windows still rejects it. Your WDAC/App Control policy must allow the AJNAT publisher or this exact package hash.'
    } else {
        'For the AJNAT local-test build, provide the matching .cer file and add -TrustLocalTestPublisher.'
    }
    throw "Package signature is not trusted (status: $($signature.Status)). $hint"
}

Write-Host "AJNAT package verified" -ForegroundColor Green
Write-Host "  SHA-256 : $actualSha256"
Write-Host "  Publisher: $($signature.SignerCertificate.Subject)"
Write-Host "  System ID: $existingSystemId"
Write-Host 'Starting installed-agent update...'

try {
    if ($extension -eq '.msi') {
        $arguments = @('/i', $PackagePath, '/qn', '/norestart', '/L*v', $installerLog)
        $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $arguments -Wait -PassThru
    } else {
        # AJNAT's NSIS update package starts its bounded updater asynchronously
        # in silent mode. The log polling below waits for the real result.
        $process = Start-Process -FilePath $PackagePath -ArgumentList @('/S') -Wait -PassThru
    }
} catch {
    if ($_.Exception.NativeErrorCode -eq 4551 -or $_.Exception.Message -match '4551|Application Control') {
        throw "Windows Application Control blocked the package (4551). Add publisher thumbprint $($signature.SignerCertificate.Thumbprint) or package SHA-256 $actualSha256 to the managed WDAC allow policy, deploy that policy, and run this script again."
    }
    throw
}

if ($process.ExitCode -notin @(0, 3010)) {
    if ($process.ExitCode -in @(1625, 4551)) {
        throw "Windows Application Control blocked the package ($($process.ExitCode)). Add publisher thumbprint $($signature.SignerCertificate.Thumbprint) or package SHA-256 $actualSha256 to the managed WDAC allow policy, deploy that policy, and run this script again. Log: $installerLog"
    }
    throw "AJNAT update failed with exit code $($process.ExitCode). Log: $installerLog"
}

if ($extension -eq '.exe') {
    Write-Host 'EXE accepted; waiting for its bounded updater to finish...'
    $deadline = (Get-Date).AddMinutes(12)
    $otaCompleted = $false
    do {
        Start-Sleep -Seconds 2
        if (Test-Path -LiteralPath $otaLog) {
            $newOtaLines = @(Get-Content -LiteralPath $otaLog | Select-Object -Skip $otaLineCount)
            if ($newOtaLines -match 'bounded OTA failed:') {
                throw "AJNAT EXE updater failed. Log: $otaLog"
            }
            if ($newOtaLines -match 'bounded OTA completed and service is running') {
                $otaCompleted = $true
            }
        }
    } while (-not $otaCompleted -and (Get-Date) -lt $deadline)

    if (-not $otaCompleted) {
        throw "The EXE bootstrap returned but its updater did not report completion within 12 minutes. Check $otaLog and Windows CodeIntegrity events."
    }
}

$updatedConfigPath = $configCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $updatedConfigPath) {
    throw 'The AJNAT enrollment config is missing after the update.'
}
$updatedConfig = Read-AjnatConfig $updatedConfigPath
if ([string]$updatedConfig.agent_key -ne $existingAgentKey -or [string]$updatedConfig.system_id -ne $existingSystemId) {
    throw 'The update changed the existing enrollment identity. Do not continue; inspect the MSI log and config backup.'
}

$service = Get-Service -Name $ServiceName -ErrorAction Stop
if ($service.Status -ne 'Running') {
    Start-Service -Name $ServiceName
    $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
}

$version = if ($updatedConfig.agent_version) { [string]$updatedConfig.agent_version } else { 'not reported' }
Write-Host ''
Write-Host "SUCCESS: AJNAT SOC Agent updated to $version and is running." -ForegroundColor Green
Write-Host "Enrollment preserved: $existingSystemId"
Write-Host "Update log: $(if ($extension -eq '.msi') { $installerLog } else { $otaLog })"
if ($process.ExitCode -eq 3010) {
    Write-Warning 'Windows requested a reboot to finish the update.'
}
