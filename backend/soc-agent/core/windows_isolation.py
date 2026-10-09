"""PowerShell for reversible Windows network isolation.

Run elevated through fw_backend._run. Managed (GPO) allow rules fail closed
before policy changes, since this agent cannot override their owner.
"""
import ipaddress

_SETUP = r'''
$ErrorActionPreference = 'Stop'
$stateDir = Join-Path $env:ProgramData 'AJNAT\Isolation'
$statePath = Join-Path $stateDir 'firewall-state.json'
$ruleName = 'AJNAT-SOC-Isolation-Management'
$mutex = [Threading.Mutex]::new($false, 'Global\AJNAT-SOC-Isolation')
if (-not $mutex.WaitOne(10000)) { throw 'Another isolation operation is running' }
function Restore-SocFirewall {
    if (-not (Test-Path -LiteralPath $statePath)) {
        $owned = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { $_.Name -eq $ruleName -or $_.DisplayName -eq 'SOC Management Allow' })
        if (-not $owned.Count) { return } # already restored; preserve unrelated policy
        throw 'Saved Windows firewall policy is missing; refusing to replace it with defaults'
    }
    $saved = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
    foreach ($profile in $saved.Profiles) {
        Set-NetFirewallProfile -PolicyStore PersistentStore -Name $profile.Name -Enabled $profile.Enabled -DefaultInboundAction $profile.DefaultInboundAction -DefaultOutboundAction $profile.DefaultOutboundAction
    }
    foreach ($name in $saved.AllowRules) {
        $rule = Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue
        if ($rule) { $rule | Set-NetFirewallRule -Enabled True }
    }
    Get-NetFirewallRule -PolicyStore PersistentStore -Name $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Remove-Item -LiteralPath $statePath -Force
}
'''


def isolation_script(management_ip, management_port):
    # Validate before embedding values into PowerShell source.
    address = str(ipaddress.ip_address(management_ip))
    port = int(management_port)
    if not 1 <= port <= 65535:
        raise ValueError('Invalid management port')
    return _SETUP + r'''
try {
    $allowed = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Action Allow | Where-Object { $_.Name -ne $ruleName })
    if (@($allowed | Where-Object { $_.PolicyStoreSourceType -ne 'Local' }).Count) {
        throw 'Group Policy contains allow rules; isolation requires the policy administrator'
    }
    if (-not (Test-Path -LiteralPath $statePath)) {
        New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
        # Only Administrators and SYSTEM may alter the restoration snapshot.
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
            $identity = [Security.Principal.SecurityIdentifier]::new($sid)
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        }
        Set-Acl -LiteralPath $stateDir -AclObject $acl
        $profiles = @(Get-NetFirewallProfile -PolicyStore PersistentStore | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction)
        @{ Profiles = $profiles; AllowRules = @($allowed | Select-Object -ExpandProperty Name) } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $statePath -Encoding UTF8
    }
    try {
        Get-NetFirewallRule -PolicyStore PersistentStore -Name $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
''' + f"""        New-NetFirewallRule -PolicyStore PersistentStore -Name $ruleName -DisplayName 'AJNAT SOC isolation management' -Direction Outbound -Action Allow -Enabled True -Profile Any -Protocol TCP -RemoteAddress '{address}' -RemotePort {port} | Out-Null
""" + r'''
        foreach ($rule in $allowed) {
            Set-NetFirewallRule -PolicyStore PersistentStore -Name $rule.Name -Enabled False
        }
        Set-NetFirewallProfile -PolicyStore PersistentStore -Name Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
        $remaining = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Action Allow | Where-Object { $_.Name -ne $ruleName })
        $openProfiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { $_.Enabled -ne 'True' -or $_.DefaultInboundAction -ne 'Block' -or $_.DefaultOutboundAction -ne 'Block' })
        if ($remaining.Count -or $openProfiles.Count) { throw 'Effective Windows firewall policy did not apply isolation' }
        Write-Output 'AJNAT isolation confirmed'
    } catch {
        $failure = $_
        Restore-SocFirewall
        throw $failure
    }
} finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
'''


def restoration_script():
    return _SETUP + r'''
try {
    Restore-SocFirewall
    Write-Output 'AJNAT reconnect confirmed'
} finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
'''
