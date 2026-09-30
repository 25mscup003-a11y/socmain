#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\AJNAT",
    [string]$DataDir = "$env:ProgramData\AJNAT",
    [string]$ConfigPath = "",
    [string]$SuricataInstallerUrl = "",
    [string]$SuricataInstallerSha256 = "",
    [string]$WinDivertFilter = "",
    [switch]$ForwardTraffic,
    [switch]$SkipRuleUpdate,
    [switch]$Optional
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$suricataServiceName = 'Suricata'
$sensorStateDir = Join-Path $DataDir 'state'
$sensorLogDir = Join-Path $DataDir 'suricata\log'
$sensorStatePath = Join-Path $sensorStateDir 'packet-ids.json'

function Find-SuricataExecutable {
    $command = Get-Command 'suricata.exe' -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $candidates = @(
        (Join-Path $env:ProgramFiles 'Suricata\suricata.exe'),
        (Join-Path $env:ProgramFiles 'Suricata\bin\suricata.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Suricata\suricata.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Suricata\bin\suricata.exe')
    )
    return $candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
}

function Install-WithWinget([string[]]$PackageIds) {
    $winget = Get-Command 'winget.exe' -ErrorAction SilentlyContinue
    if (-not $winget) { return $false }
    foreach ($packageId in $PackageIds) {
        & $winget.Source install --id $packageId --exact --silent --disable-interactivity --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -eq 0) { return $true }
    }
    return $false
}

function Install-WithChocolatey([string]$PackageName, [string[]]$Arguments = @()) {
    $choco = Get-Command 'choco.exe' -ErrorAction SilentlyContinue
    if (-not $choco) { return $false }
    & $choco.Source install $PackageName -y --no-progress @Arguments
    return $LASTEXITCODE -eq 0
}

function Install-SignedPackageFromUrl([string]$Url, [string]$Name, [string]$Sha256 = '') {
    if ([string]::IsNullOrWhiteSpace($Url)) { return $false }
    $uri = [Uri]$Url
    if ($uri.Scheme -ne 'https') { throw "$Name installer URL must use HTTPS" }
    $extension = [IO.Path]::GetExtension($uri.AbsolutePath).ToLowerInvariant()
    if ($extension -notin @('.exe', '.msi')) { throw "$Name installer must be an EXE or MSI" }
    $packageDir = Join-Path $InstallDir 'packages'
    New-Item -ItemType Directory -Path $packageDir -Force | Out-Null
    $download = Join-Path $packageDir ("AJNAT-{0}-{1}{2}" -f $Name, [guid]::NewGuid().ToString('N'), $extension)
    try {
        Invoke-WebRequest -Uri $Url -OutFile $download -UseBasicParsing -TimeoutSec 300
        if ($Sha256) {
            $actual = (Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash
            if ($actual -ne $Sha256.Trim().ToUpperInvariant()) { throw "$Name installer SHA-256 mismatch" }
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $download
        if ($signature.Status -ne 'Valid') { throw "$Name installer signature is not valid: $($signature.Status)" }
        if ($extension -eq '.msi') {
            $process = Start-Process msiexec.exe -ArgumentList @('/i', $download, '/qn', '/norestart') -Wait -PassThru
        } else {
            $process = Start-Process $download -ArgumentList @('/S') -Wait -PassThru
        }
        if ($process.ExitCode -notin @(0, 1641, 3010)) { throw "$Name installer failed with exit code $($process.ExitCode)" }
        return $true
    } finally {
        Remove-Item -LiteralPath $download -Force -ErrorAction SilentlyContinue
    }
}

function Install-Suricata {
    $inlineInstallerUrl = if ($SuricataInstallerUrl) { $SuricataInstallerUrl } else { $env:AJNAT_SURICATA_INSTALLER_URL }
    $inlineInstallerSha256 = if ($SuricataInstallerSha256) { $SuricataInstallerSha256 } else { $env:AJNAT_SURICATA_INSTALLER_SHA256 }
    if ($inlineInstallerUrl -and -not $inlineInstallerSha256) {
        throw 'A pinned SHA-256 is required with the custom WinDivert-capable Suricata installer URL.'
    }
    $executable = Find-SuricataExecutable
    if ($executable) {
        try {
            Assert-SuricataWinDivert $executable
            return $executable
        } catch {
            if (-not $inlineInstallerUrl) { throw }
            Write-Host '  Replacing non-WinDivert Suricata with the configured inline-capable build ...' -ForegroundColor Yellow
        }
    } else {
        Write-Host '  Installing WinDivert-capable Suricata ...' -ForegroundColor Yellow
    }
    $installed = $false
    if ($inlineInstallerUrl) {
        $installed = Install-SignedPackageFromUrl $inlineInstallerUrl 'suricata' $inlineInstallerSha256
    }
    if (-not $installed) { $installed = Install-WithWinget @('OISF.Suricata') }
    if (-not $installed) { $installed = Install-WithChocolatey 'suricata' }
    $executable = Find-SuricataExecutable
    if (-not $installed -or -not $executable) {
        throw 'Suricata installation failed. Configure AJNAT_SURICATA_INSTALLER_URL (and SHA256) or install Suricata before retrying.'
    }
    Assert-SuricataWinDivert $executable
    return $executable
}

function Find-SuricataConfig([string]$Executable) {
    $root = Split-Path -Parent $Executable
    if ((Split-Path -Leaf $root) -eq 'bin') { $root = Split-Path -Parent $root }
    $candidates = @(
        (Join-Path $root 'suricata.yaml'),
        (Join-Path $root 'etc\suricata\suricata.yaml'),
        (Join-Path $env:ProgramData 'Suricata\suricata.yaml')
    )
    $config = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $config) { throw 'Suricata configuration file was not found after installation' }
    return $config
}

function Assert-SuricataWinDivert([string]$Executable) {
    $executableDir = Split-Path -Parent $Executable
    $buildInfo = (& $Executable --build-info 2>&1 | Out-String)
    $helpText = (& $Executable --help 2>&1 | Out-String)
    if ($buildInfo -notmatch '(?im)^\s*WinDivert enabled:\s+yes\s*$' -or
        $helpText -notmatch '(?m)--windivert(?:-forward)?\b') {
        throw 'Installed Suricata was not compiled with WinDivert. Install an OISF Windows build with WinDivert support or set AJNAT_SURICATA_INSTALLER_URL to a signed compatible installer.'
    }
    $winDivertDll = Join-Path $executableDir 'WinDivert.dll'
    $winDivertDriver = Get-ChildItem -LiteralPath $executableDir -Filter 'WinDivert*.sys' -File -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not (Test-Path -LiteralPath $winDivertDll) -or -not $winDivertDriver) {
        throw "Suricata has WinDivert CLI support but WinDivert.dll/WinDivert*.sys are missing beside $Executable"
    }
}

function Update-AgentSensorConfig([string]$EvePath, [string]$SuricataConfig, [string]$SuricataExecutable) {
    if (-not $ConfigPath) {
        $ConfigPath = @(
            (Join-Path $DataDir 'config\company_config.json'),
            (Join-Path $InstallDir 'config\company_config.json')
        ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    }
    if (-not $ConfigPath -or -not (Test-Path -LiteralPath $ConfigPath)) { return }
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    foreach ($setting in @{
        ids_enabled = $true
        network_ids_sensors_enabled = $true
        suricata_eve_path = $EvePath
        packet_sensor_provider = 'suricata-windivert'
        packet_ids_mode = 'suricata-windivert-inline'
        ips_enabled = $true
        ips_auto_block = $true
        network_attack_block_enabled = $true
        ips_enforcement_mode = 'suricata-inline-windivert+defender-firewall'
        inline_packet_verdict = $true
        suricata_config = $SuricataConfig
        suricata_soc_rules = (Join-Path (Split-Path -Parent $SuricataConfig) 'rules\soc-managed.rules')
        suricata_executable = $SuricataExecutable
        waf_enabled = $true
        waf_direct_block_enabled = $true
        waf_direct_block_threshold = 'medium'
    }.GetEnumerator()) {
        if ($config.PSObject.Properties.Name -contains $setting.Key) {
            $config.($setting.Key) = $setting.Value
        } else {
            $config | Add-Member -NotePropertyName $setting.Key -NotePropertyValue $setting.Value
        }
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($ConfigPath, ($config | ConvertTo-Json -Depth 30), $utf8NoBom)
}

try {
    Write-Host 'Configuring Windows inline IPS (Suricata + WinDivert) ...' -ForegroundColor Yellow
    $suricata = Install-Suricata
    $suricataConfig = Find-SuricataConfig $suricata
    Assert-SuricataWinDivert $suricata
    if (-not $WinDivertFilter) { $WinDivertFilter = $env:AJNAT_SURICATA_WINDIVERT_FILTER }
    if (-not $WinDivertFilter) { $WinDivertFilter = 'true' }
    $winDivertOption = if ($ForwardTraffic -or $env:AJNAT_SURICATA_WINDIVERT_FORWARD -eq '1') {
        '--windivert-forward'
    } else {
        '--windivert'
    }
    $winDivertLayer = if ($winDivertOption -eq '--windivert-forward') { 'network-forward' } else { 'network' }
    New-Item -ItemType Directory -Path $sensorLogDir,$sensorStateDir -Force | Out-Null

    & $suricata -T -c $suricataConfig -l $sensorLogDir
    if ($LASTEXITCODE -ne 0) { throw "Suricata configuration validation failed with exit code $LASTEXITCODE" }

    $suricataRoot = Split-Path -Parent $suricata
    if ((Split-Path -Leaf $suricataRoot) -eq 'bin') { $suricataRoot = Split-Path -Parent $suricataRoot }
    $ruleUpdater = @(
        (Join-Path $suricataRoot 'suricata-update.exe'),
        (Join-Path $suricataRoot 'bin\suricata-update.exe'),
        (Get-Command 'suricata-update.exe' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue)
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    if ($ruleUpdater -and -not $SkipRuleUpdate) {
        $ruleUpdateProcess = Start-Process -FilePath $ruleUpdater -ArgumentList @('update') -PassThru -WindowStyle Hidden
        if (-not $ruleUpdateProcess.WaitForExit(60000)) {
            try { $ruleUpdateProcess.Kill() } catch {}
            Write-Host '  WARN: Suricata online rule update timed out; installed rules will be used.' -ForegroundColor Yellow
        } elseif ($ruleUpdateProcess.ExitCode -ne 0) {
            Write-Host '  WARN: Suricata online rule update failed; installed rules will be used.' -ForegroundColor Yellow
        }
    } elseif ($SkipRuleUpdate) {
        Write-Host '  INFO: Keeping installed Suricata rules during agent update.' -ForegroundColor Gray
    }

    $service = Get-Service -Name $suricataServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        & $suricata --service-install
        if ($LASTEXITCODE -ne 0) { throw "Suricata service installation failed with exit code $LASTEXITCODE" }
    } elseif ($service.Status -ne 'Stopped') {
        Stop-Service -Name $suricataServiceName -Force
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    $serviceArguments = @(
        '--service-change-params', '-c', $suricataConfig, '-l', $sensorLogDir,
        $winDivertOption, $WinDivertFilter
    )
    & $suricata @serviceArguments
    if ($LASTEXITCODE -ne 0) { throw "Suricata service configuration failed with exit code $LASTEXITCODE" }
    Set-Service -Name $suricataServiceName -StartupType Automatic
    Restart-Service -Name $suricataServiceName -Force
    (Get-Service -Name $suricataServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    $serviceCommand = [string](Get-CimInstance Win32_Service -Filter "Name='$suricataServiceName'").PathName
    if ($serviceCommand -notmatch '--windivert(?:-forward)?\b') {
        throw 'Suricata service started without a WinDivert inline capture argument'
    }

    $evePath = Join-Path $sensorLogDir 'eve.json'
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline -and -not (Test-Path -LiteralPath $evePath)) { Start-Sleep -Seconds 1 }
    if (-not (Test-Path -LiteralPath $evePath)) { throw 'Suricata is running but eve.json was not created' }

    Update-AgentSensorConfig $evePath $suricataConfig $suricata
    @{
        provider = 'suricata-windivert'
        service = $suricataServiceName
        executable = $suricata
        capture_backend = 'windivert'
        capture_layer = $winDivertLayer
        capture_filter = $WinDivertFilter
        eve_path = $evePath
        ids_mode = 'inline-packet-detection'
        ips_mode = 'suricata-windivert-inline'
        firewall_escalation = 'windows-defender-firewall'
        inline_packet_verdict = $true
        configured_at = (Get-Date).ToUniversalTime().ToString('o')
    } | ConvertTo-Json | Set-Content -LiteralPath $sensorStatePath -Encoding UTF8
    Write-Host "  OK: Suricata inline IPS is enforcing packet verdicts via WinDivert ($winDivertLayer layer)" -ForegroundColor Green
    Write-Host '  OK: Windows Defender Firewall will also retain alert-derived source-IP blocks' -ForegroundColor Green
    Write-Host "  OK: EVE events: $evePath" -ForegroundColor Green
    exit 0
} catch {
    $message = $_.Exception.Message
    $level = if ($Optional) { 'WARN' } else { 'ERROR' }
    $color = if ($Optional) { 'Yellow' } else { 'Red' }
    Write-Host ("  {0}: Windows Suricata inline IPS setup failed: {1}" -f $level, $message) -ForegroundColor $color
    New-Item -ItemType Directory -Path $sensorStateDir -Force | Out-Null
    @{
        provider = $(if ($Optional) { 'windows-defender-firewall' } else { 'suricata-windivert' })
        status = $(if ($Optional) { 'degraded' } else { 'failed' })
        ids_mode = $(if ($Optional) { 'network-change-and-firewall-telemetry' } else { 'unavailable' })
        ips_mode = $(if ($Optional) { 'native-ip-block-after-detection' } else { 'unavailable' })
        inline_packet_verdict = $false
        firewall_escalation = 'windows-defender-firewall'
        error = $message
        configured_at = (Get-Date).ToUniversalTime().ToString('o')
    } | ConvertTo-Json | Set-Content -LiteralPath $sensorStatePath -Encoding UTF8
    if ($Optional) {
        if (-not $ConfigPath) {
            $ConfigPath = @(
                (Join-Path $DataDir 'config\company_config.json'),
                (Join-Path $InstallDir 'config\company_config.json')
            ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        }
        if ($ConfigPath -and (Test-Path -LiteralPath $ConfigPath)) {
            try {
                $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
                foreach ($setting in @{
                    packet_sensor_provider = 'windows-defender-firewall'
                    packet_ids_mode = 'network-change-and-firewall-telemetry'
                    ips_enforcement_mode = 'windows-defender-firewall'
                    inline_packet_verdict = $false
                    network_ids_sensors_enabled = $false
                    ips_enabled = $true
                    firewall_enabled = $true
                }.GetEnumerator()) {
                    if ($config.PSObject.Properties.Name -contains $setting.Key) {
                        $config.($setting.Key) = $setting.Value
                    } else {
                        $config | Add-Member -NotePropertyName $setting.Key -NotePropertyValue $setting.Value
                    }
                }
                $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
                [IO.File]::WriteAllText($ConfigPath, ($config | ConvertTo-Json -Depth 30), $utf8NoBom)
            } catch {
                Write-Host "  WARN: Could not persist degraded sensor state: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        Write-Host '  Continuing with Windows Defender Firewall native IPS fallback.' -ForegroundColor Yellow
        exit 0
    }
    exit 1
}
