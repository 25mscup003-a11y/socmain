#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\AJNAT",
    [string]$SysmonDownloadUrl = 'https://download.sysinternals.com/files/Sysmon.zip',
    [switch]$SkipSysmonDownload
)

$ErrorActionPreference = 'Stop'
$statusDir = Join-Path $env:ProgramData 'AJNAT\state'
New-Item -ItemType Directory -Path $statusDir -Force | Out-Null
$statusPath = Join-Path $statusDir 'advanced-process-telemetry.json'
$status = [ordered]@{
    configuredAt = (Get-Date).ToUniversalTime().ToString('o')
    processCreationAudit = $false
    commandLineAudit = $false
    powershellOperational = $false
    taskSchedulerOperational = $false
    sysmonInstalled = $false
    sysmonConfigured = $false
    sysmonDownloadAttempted = $false
    sysmonSource = $null
}

function Test-AjnatMicrosoftSysmon {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        return $signature.Status -eq 'Valid' -and
            $signature.SignerCertificate -and
            $signature.SignerCertificate.Subject -match 'Microsoft'
    } catch {
        return $false
    }
}

try {
    # Process Creation audit subcategory GUID is locale independent.
    & auditpol.exe /set /subcategory:'{0CCE922B-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null
    if ($LASTEXITCODE -eq 0) { $status.processCreationAudit = $true }
} catch {}

try {
    $auditKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    New-Item -Path $auditKey -Force | Out-Null
    New-ItemProperty -Path $auditKey -Name ProcessCreationIncludeCmdLine_Enabled -PropertyType DWord -Value 1 -Force | Out-Null
    $status.commandLineAudit = $true
} catch {}

try {
    $scriptBlockKey = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    New-Item -Path $scriptBlockKey -Force | Out-Null
    New-ItemProperty -Path $scriptBlockKey -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force | Out-Null
} catch {}

foreach ($channel in @(
    'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-DNS-Client/Operational'
)) {
    try {
        & wevtutil.exe sl $channel /e:true | Out-Null
        if ($LASTEXITCODE -eq 0) {
            if ($channel -like '*PowerShell*') { $status.powershellOperational = $true }
            if ($channel -like '*TaskScheduler*') { $status.taskSchedulerOperational = $true }
        }
    } catch {}
}

$sysmonService = Get-Service -Name Sysmon64,Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1
$sysmonCommand = Get-Command Sysmon64.exe,Sysmon.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$sysmonServiceBinary = $null
try {
    $sysmonServiceInfo = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
        Where-Object { $_.Name -in @('Sysmon64', 'Sysmon') } |
        Select-Object -First 1
    if ($sysmonServiceInfo -and $sysmonServiceInfo.PathName -match '^\s*"?(?<exe>[^"].*?\.exe)"?(?:\s|$)') {
        $sysmonServiceBinary = $Matches.exe
    }
} catch {}
$sysmonExe = @(
    (Join-Path $InstallDir 'tools\Sysmon64.exe'),
    (Join-Path $InstallDir 'tools\Sysmon.exe'),
    $sysmonServiceBinary,
    $(if ($sysmonCommand) { $sysmonCommand.Source })
) | Where-Object { Test-AjnatMicrosoftSysmon $_ } | Select-Object -First 1
$sysmonConfig = Join-Path $InstallDir 'sysmon-ajnat.xml'
$sysmonConfigApplied = $false

if (-not $sysmonExe -and -not $SkipSysmonDownload -and $SysmonDownloadUrl -and (Test-Path -LiteralPath $sysmonConfig)) {
    $status.sysmonDownloadAttempted = $true
    $sysmonStage = Join-Path $env:TEMP "ajnat-sysmon-$PID"
    try {
        New-Item -ItemType Directory -Path $sysmonStage -Force | Out-Null
        $sysmonArchive = Join-Path $sysmonStage 'Sysmon.zip'
        Invoke-WebRequest -UseBasicParsing -Uri $SysmonDownloadUrl -OutFile $sysmonArchive -ErrorAction Stop
        Expand-Archive -LiteralPath $sysmonArchive -DestinationPath $sysmonStage -Force
        $downloadedSysmon = @(
            (Join-Path $sysmonStage 'Sysmon64.exe'),
            (Join-Path $sysmonStage 'Sysmon.exe')
        ) | Where-Object { Test-AjnatMicrosoftSysmon $_ } | Select-Object -First 1
        if (-not $downloadedSysmon) {
            throw 'Downloaded Sysmon package has no valid Microsoft-signed executable'
        }
        $toolsDir = Join-Path $InstallDir 'tools'
        New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
        $sysmonExe = Join-Path $toolsDir ([IO.Path]::GetFileName($downloadedSysmon))
        Copy-Item -LiteralPath $downloadedSysmon -Destination $sysmonExe -Force
        if (-not (Test-AjnatMicrosoftSysmon $sysmonExe)) {
            throw 'Installed Sysmon executable failed Microsoft signature validation'
        }
        $status.sysmonSource = 'microsoft_sysinternals_download'
    } catch {
        $sysmonExe = $null
        Write-Warning "Secure Sysmon provisioning failed: $($_.Exception.Message)"
    } finally {
        if (Test-Path -LiteralPath $sysmonStage) {
            Remove-Item -LiteralPath $sysmonStage -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
} elseif ($sysmonExe) {
    $status.sysmonSource = 'existing_microsoft_signed_binary'
}

if (-not $sysmonService -and $sysmonExe -and (Test-Path -LiteralPath $sysmonConfig)) {
    & $sysmonExe -accepteula -i $sysmonConfig | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Sysmon installation failed with exit code $LASTEXITCODE" }
    $sysmonConfigApplied = $true
    $sysmonService = Get-Service -Name Sysmon64,Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1
} elseif ($sysmonService -and $sysmonExe -and (Test-Path -LiteralPath $sysmonConfig)) {
    & $sysmonExe -c $sysmonConfig | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Sysmon configuration failed with exit code $LASTEXITCODE" }
    $sysmonConfigApplied = $true
}

if ($sysmonService) {
    $status.sysmonInstalled = $true
    $sysmonChannelAvailable = [bool](Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue)
    $status.sysmonConfigured = $sysmonConfigApplied -and $sysmonChannelAvailable
}

$status | ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding UTF8
Write-Host "Advanced process telemetry configuration written to $statusPath"
if (-not $status.sysmonInstalled) {
    Write-Warning 'Sysmon is not installed. Native process/task/service auditing is active, but DLL injection, hollowing, exact process DNS and kernel process-access coverage remains degraded.'
} elseif (-not $status.sysmonConfigured) {
    Write-Warning 'Sysmon is installed but AJNAT could not verify that its advanced telemetry configuration was applied. Coverage remains degraded.'
}
