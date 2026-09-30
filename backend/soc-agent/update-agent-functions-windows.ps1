#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
Updates only AJNAT agent program files on an already-enrolled Windows endpoint.

.DESCRIPTION
The installed company_config.json, system_id, agent_key and agent_version are
preserved. This is a source/function update, not an agent release upgrade.

.EXAMPLE
PowerShell.exe -ExecutionPolicy Bypass -File .\update-agent-functions-windows.ps1 `
  -SourceDirectory .\soc-agent
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$SourceDirectory,

    [string]$InstallDirectory = (Join-Path $env:ProgramFiles 'AJNAT'),

    [string]$ServiceName = 'SOCAgent'
)

$ErrorActionPreference = 'Stop'
$source = (Resolve-Path -LiteralPath $SourceDirectory).Path
$install = [IO.Path]::GetFullPath($InstallDirectory)
if ($source.TrimEnd('\') -eq $install.TrimEnd('\')) {
    throw 'SourceDirectory and InstallDirectory must be different.'
}

$requiredFiles = @(
    'agent.py',
    'windows_service.py',
    'requirements.txt',
    'collectors\processes.py',
    'collectors\hash_signature.py',
    'core\sender.py',
    'core\config_protection.py',
    'core\device_identity.py'
)
foreach ($relativePath in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $source $relativePath) -PathType Leaf)) {
        throw "Update source is incomplete; missing $relativePath"
    }
}

if (-not (Test-Path -LiteralPath (Join-Path $install 'agent.py') -PathType Leaf)) {
    throw "Installed AJNAT agent was not found at $install"
}
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $service) {
    throw "Installed AJNAT service '$ServiceName' was not found."
}

$dataDirectory = Join-Path $env:ProgramData 'AJNAT'
$configCandidates = @(
    (Join-Path $dataDirectory 'config\company_config.json'),
    (Join-Path $install 'config\company_config.json')
)
$configPath = $configCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $configPath) {
    throw 'Existing AJNAT enrollment config was not found. The function update has been cancelled.'
}

$pythonCandidates = @(
    (Join-Path $install 'runtime\python\python.exe'),
    (Join-Path $env:ProgramFiles 'Python313\python.exe'),
    (Join-Path $env:ProgramFiles 'Python312\python.exe')
)
$programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
if ($programFilesX86) {
    $pythonCandidates += (Join-Path $programFilesX86 'Python313\python.exe')
    $pythonCandidates += (Join-Path $programFilesX86 'Python312\python.exe')
}
$python = $pythonCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
if (-not $python) {
    throw 'The Python runtime used by AJNAT was not found.'
}
function Read-AjnatConfig([string]$Path) {
    try { return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json) } catch {}
    $json = & $python -c "import json,sys; sys.path.insert(0,sys.argv[1]); from core.config_protection import load_config; print(json.dumps(load_config(sys.argv[2])))" $source $Path
    if ($LASTEXITCODE -ne 0) { throw "Could not decrypt AJNAT enrollment config: $Path" }
    return ($json | ConvertFrom-Json)
}
$configBefore = Read-AjnatConfig $configPath
$identityBefore = @{
    agent_key = [string]$configBefore.agent_key
    system_id = [string]$configBefore.system_id
    agent_version = [string]$configBefore.agent_version
}
if (-not $identityBefore.agent_key -or -not $identityBefore.system_id) {
    throw "Installed enrollment config is incomplete: $configPath"
}
$sitePackages = ([string](& $python -c "import sysconfig; print(sysconfig.get_paths()['purelib'])")).Trim()
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $sitePackages -PathType Container)) {
    throw 'Could not resolve AJNAT Python site-packages.'
}
$serviceModule = Join-Path $sitePackages 'windows_service.py'

Write-Host '[1/6] Validating source Python files...'
$validationCode = @'
import ast
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
for path in root.rglob("*.py"):
    if "__pycache__" not in path.parts:
        ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
'@
& $python -c $validationCode $source
if ($LASTEXITCODE -ne 0) {
    throw "Source validation failed with exit code $LASTEXITCODE"
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupRoot = Join-Path $dataDirectory "backups\function-update-$stamp"
$backupApp = Join-Path $backupRoot 'app'
$backupConfig = Join-Path $backupRoot 'company_config.json'
$managedDirectories = @('collectors', 'core', 'detectors', 'response', 'yara_rules')
$managedFiles = @('agent.py', 'windows_service.py', 'requirements.txt')

Write-Host "[2/6] Creating rollback backup: $backupRoot"
New-Item -ItemType Directory -Path $backupApp -Force | Out-Null
foreach ($name in $managedDirectories + $managedFiles) {
    $existingPath = Join-Path $install $name
    if (Test-Path -LiteralPath $existingPath) {
        Copy-Item -LiteralPath $existingPath -Destination $backupApp -Recurse -Force
    }
}
Copy-Item -LiteralPath $configPath -Destination $backupConfig -Force
$backupServiceModule = Join-Path $backupRoot 'site-packages-windows_service.py'
if (Test-Path -LiteralPath $serviceModule -PathType Leaf) {
    Copy-Item -LiteralPath $serviceModule -Destination $backupServiceModule -Force
}

$filesChanged = $false
try {
    Write-Host "[3/6] Stopping $ServiceName..."
    Stop-Service -Name $ServiceName -Force
    (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))

    Write-Host '[4/6] Installing monitoring function files...'
    foreach ($name in $managedDirectories) {
        $sourcePath = Join-Path $source $name
        if (-not (Test-Path -LiteralPath $sourcePath -PathType Container)) { continue }
        $targetPath = Join-Path $install $name
        New-Item -ItemType Directory -Path $targetPath -Force | Out-Null
        Copy-Item -Path (Join-Path $sourcePath '*') -Destination $targetPath -Recurse -Force
    }
    foreach ($name in $managedFiles) {
        Copy-Item -LiteralPath (Join-Path $source $name) -Destination (Join-Path $install $name) -Force
    }
    Get-ChildItem -LiteralPath $install -Directory -Filter '__pycache__' -Recurse -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    $filesChanged = $true

    # The native Windows service host imports this module from site-packages.
    Copy-Item -LiteralPath (Join-Path $install 'windows_service.py') -Destination $serviceModule -Force

    Write-Host '[5/6] Confirming enrollment and version were preserved...'
    $configAfter = Read-AjnatConfig $configPath
    if ([string]$configAfter.agent_key -ne $identityBefore.agent_key -or
        [string]$configAfter.system_id -ne $identityBefore.system_id -or
        [string]$configAfter.agent_version -ne $identityBefore.agent_version) {
        throw 'Enrollment identity or agent_version changed during the function update.'
    }

    Write-Host "[6/6] Starting and verifying $ServiceName..."
    Start-Service -Name $ServiceName
    (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    Start-Sleep -Seconds 3
    if ((Get-Service -Name $ServiceName).Status -ne 'Running') {
        throw "$ServiceName did not remain running after the function update."
    }
} catch {
    $failure = $_
    Write-Warning "Function update failed: $($failure.Exception.Message)"
    if ($filesChanged) {
        Write-Warning 'Restoring previous agent files...'
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        foreach ($name in $managedDirectories + $managedFiles) {
            $targetPath = Join-Path $install $name
            Remove-Item -LiteralPath $targetPath -Recurse -Force -ErrorAction SilentlyContinue
            $savedPath = Join-Path $backupApp $name
            if (Test-Path -LiteralPath $savedPath) {
                Copy-Item -LiteralPath $savedPath -Destination $install -Recurse -Force
            }
        }
        Copy-Item -LiteralPath $backupConfig -Destination $configPath -Force
        if (Test-Path -LiteralPath $backupServiceModule -PathType Leaf) {
            Copy-Item -LiteralPath $backupServiceModule -Destination $serviceModule -Force
        }
    }
    Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
    throw $failure
}

Write-Host ''
Write-Host 'SUCCESS: AJNAT monitoring functions updated; release version was not changed.' -ForegroundColor Green
Write-Host "System ID : $($identityBefore.system_id)"
Write-Host "Version   : $($identityBefore.agent_version)"
Write-Host "Backup    : $backupRoot"
