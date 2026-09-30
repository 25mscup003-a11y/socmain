"""
Rule-based log detector — analyzes every new log line against 40+ regex rules.
Correctly sets category so backend saves the right eventCategory.
"""

import re
import logging
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Optional

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9 fallback
    ZoneInfo = None

logger = logging.getLogger('soc-agent.detector.rules')

# ─── Rule table ───────────────────────────────────────────────────────────────
# cat values: malware / network / file / system / edr / usb / auth
RULES = [
    # ── Authentication ────────────────────────────────────────────────────────
    dict(id='AUTH_SCREEN_LOCK', cat='edr', sev='low',
         pat=r'(EventID=4800\b|workstation (?:was )?locked|screen[ _-]?lock(?:ed| activated))',
         desc='Workstation or desktop session locked'),
    dict(id='AUTH_SCREEN_UNLOCK_FAILURE', cat='edr', sev='medium',
         pat=r'(EventID=4625[\s\S]*?Logon Type:\s*7\b|pam_unix\((?:gdm-password|lightdm|xscreensaver|kscreenlocker|loginwindow):auth\):\s*authentication failure|(?:Windows Hello|\bPIN\b|biometric|screen[ _-]?unlock)[^\r\n]*(?:fail|invalid|denied))',
         desc='Invalid or rejected lock-screen unlock authentication'),
    dict(id='AUTH_SCREEN_UNLOCK_SUCCESS', cat='edr', sev='low',
         pat=r'(EventID=4801\b|EventID=4624[\s\S]*?Logon Type:\s*7\b|workstation (?:was )?unlocked|pam_unix\((?:gdm-password|lightdm|xscreensaver|kscreenlocker|loginwindow):auth\):\s*authentication success|screen[ _-]?unlock[^\r\n]*(?:success|succeeded))',
         desc='Successful lock-screen unlock authentication'),
    dict(id='AUTH_FAIL',       cat='edr',     sev='medium',
         pat=r'(Failed password|authentication failure|Invalid user|pam_unix.*auth.*failed|EventID=4625|EventID=4771|EventID=4776[\s\S]*?(?:Error Code|Status):\s*(?!0x0\b)0x[0-9a-f]+)',
         desc='Authentication failure'),
    dict(id='AUTH_SUCCESS',    cat='edr',     sev='low',
         pat=r'(Accepted (password|publickey|keyboard-interactive)|session opened for user|EventID=4624|EventID=4768|EventID=4769|EventID=4776[\s\S]*?(?:Error Code|Status):\s*0x0\b)',
         desc='Successful authentication'),
    dict(id='AUTH_LOGOUT',     cat='edr',     sev='low',
         pat=r'(session closed for user|Disconnected from user|EventID=4634|EventID=4647)',
         desc='User logout / session ended'),
    dict(id='AUTH_BRUTE',      cat='edr',     sev='high',
         pat=r'(repeated login failures|too many auth failures|maximum authentication attempts|FAILED LOGIN.*\b[5-9]\b|FAILED LOGIN.*\b[1-9]\d|brute force|password spray|password spraying|credential stuffing)',
         desc='Brute force login attempt'),
    dict(id='AUTH_ROOT_LOGIN', cat='edr',     sev='critical',
         pat=r'(root login accepted|Accepted.*root|su.*root.*succeeded|sudo.*root)',
         desc='Root login detected'),
    dict(id='AUTH_SUDO',       cat='edr',     sev='medium',
         pat=r'sudo:.*COMMAND|pam_sudo|not in sudoers',
         desc='Sudo command executed'),
    dict(id='AUTH_SSH_KEY',    cat='edr',     sev='medium',
         pat=r'(Accepted publickey|Accepted keyboard-interactive)',
         desc='SSH key authentication'),
    dict(id='AUTH_PASS_CHANGE',cat='edr',     sev='medium',
         pat=r'(password changed|passwd.*changed|chpasswd|EventID=4723|EventID=4724)',
         desc='Password changed'),
    dict(id='AUTH_ACCOUNT_LOCK', cat='edr',   sev='high',
         pat=r'(account.*locked|too many failed.*login|account disabled due|EventID=4740)',
         desc='Account locked out'),
    dict(id='AUTH_USER_CREATED', cat='edr',   sev='high',
         pat=r'(new user:|useradd|adduser|net\s+user\s+\S+\s+/add|New-LocalUser|EventID=4720)',
         desc='New user account created'),
    dict(id='AUTH_USER_DELETED', cat='edr',   sev='high',
         pat=r'(userdel|delete user|net\s+user\s+\S+\s+/delete|Remove-LocalUser|EventID=4726)',
         desc='User account deleted'),
    dict(id='AUTH_USER_MODIFIED', cat='edr',  sev='medium',
         pat=r'(usermod|chage|account.*modified|user account.*changed|Set-LocalUser|EventID=4738)',
         desc='User account modified'),
    dict(id='AUTH_GROUP_CHANGE', cat='edr',   sev='high',
         pat=r'(groupadd|groupdel|gpasswd|usermod.*(-aG|--append)|net\s+localgroup|Add-LocalGroupMember|Remove-LocalGroupMember|EventID=4728|EventID=4729|EventID=4732|EventID=4733|EventID=4756|EventID=4757)',
         desc='Group membership changed'),
    dict(id='AUTH_ADMIN_RIGHTS', cat='edr',   sev='high',
         pat=r'(administrators|sudoers|wheel|Domain Admins|Enterprise Admins|EventID=4672)',
         desc='Administrative rights assigned or used'),
    dict(id='AUTH_REMOTE_ACCESS', cat='edr',  sev='medium',
         pat=r'(sshd|ssh2|RDP|Remote Desktop|Logon Type:\s*(3|10)|EventID=1149|vpn|openvpn|wireguard|strongswan|pppd|GlobalProtect|AnyConnect)',
         desc='Remote access authentication'),
    dict(id='AUTH_MFA_SUCCESS', cat='edr',    sev='low',
         pat=r'(mfa.*success|2fa.*success|otp.*verified|totp.*verified|duo.*success)',
         desc='MFA success'),
    dict(id='AUTH_MFA_FAILURE', cat='edr',    sev='high',
         pat=r'(mfa.*fail|2fa.*fail|otp.*fail|totp.*fail|duo.*denied|mfa.*bypass)',
         desc='MFA failure or bypass attempt'),
    dict(id='AUTH_POLICY_VIOLATION', cat='edr', sev='medium',
         pat=r'(password policy|policy violation|minimum password|complexity requirements|EventID=4739)',
         desc='Password or authentication policy violation'),
    dict(id='AUTH_EXPLICIT_CREDENTIALS', cat='edr', sev='medium',
         pat=r'(EventID=4648|explicit credentials|runas)',
         desc='Credential validation or explicit credential use'),
    dict(id='AUTH_ACCOUNT_ENABLED_DISABLED', cat='edr', sev='high',
         pat=r'(EventID=4722|EventID=4725|account (?:enabled|disabled)|disabled account.*(?:login|logon))',
         desc='Account enabled, disabled, or used while disabled'),
    dict(id='AUTH_ACCOUNT_ENUMERATION', cat='edr', sev='medium',
         pat=r'(EventID=4798|EventID=4799|local group membership enumerat|account group membership enumerat)',
         desc='Account or privileged group membership enumerated'),
    dict(id='AUTH_SSH_KEY_CHANGE', cat='edr', sev='high',
         pat=r'(authorized_keys.*(?:writ|creat|modif|chang)|ssh key.*(?:added|changed|removed)|AuthorizedKeysCommand)',
         desc='SSH authorized key configuration changed'),
    dict(id='AUTH_TOKEN_ABUSE', cat='edr', sev='critical',
         pat=r'(token replay|session hijack|refresh token abuse|jwt abuse|oauth abuse|suspicious token|token duplication)',
         desc='Session or authentication token abuse detected'),
    dict(id='AUTH_CLOUD_IAM_ABUSE', cat='edr', sev='high',
         pat=r'((?:aws iam|azure ad|entra id|google workspace|okta|cloud iam).*(?:abuse|unauthori[sz]ed|suspicious|privilege|api key|access key)|(?:api key|access key).*(?:leak|expos|abuse))',
         desc='Cloud identity or API key abuse detected'),
    dict(id='AUTH_CREDENTIAL_STORE_ACCESS', cat='edr', sev='critical',
         pat=r'(lsass.*(?:access|dump)|sam (?:database|dump)|credential manager|windows vault|dpapi|browser password|keychain access|/etc/(?:shadow|gshadow)|\.aws/credentials)',
         desc='Credential store access or dumping activity detected'),

    # ── Malware / Shells ──────────────────────────────────────────────────────
    dict(id='SHELL_REVERSE',   cat='malware', sev='critical',
         pat=r'(/dev/tcp/|/dev/udp/|bash -i|bash.*>&.*&>|nc -e|ncat -e|python.*socket|perl.*socket.*exec)',
         desc='Reverse shell attempt'),
    dict(id='SHELL_WEB',       cat='malware', sev='critical',
         pat=r'(eval\(base64_decode|eval\(gzinflate|system\(\$_GET|passthru\(\$_POST|cmd\.exe.*echo|certutil.*decode)',
         desc='Web shell activity'),
    dict(id='MALWARE_DOWNLOAD',cat='malware', sev='high',
         pat=r'(wget.*http.*\.exe|curl.*http.*\.sh|powershell.*DownloadFile|bitsadmin.*transfer)',
         desc='Malware download attempt'),
    dict(id='MALWARE_MINER',   cat='malware', sev='high',
         pat=r'(xmrig|stratum\+tcp|stratum\+ssl|monero|cryptonight|nicehash)',
         desc='Crypto miner detected'),
    dict(id='RANSOMWARE_SHADOW',cat='malware',sev='critical',
         pat=r'(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled.*no|wbadmin.*delete.*catalog)',
         desc='Shadow copy deletion — ransomware indicator'),
    dict(id='RANSOMWARE_EXT',  cat='malware', sev='critical',
         pat=r'\.(locked|encrypted|crypt|zzzzz|wncry|ryuk|cerber|locky|wannacry)\b',
         desc='Ransomware file extension detected'),
    dict(id='MALWARE_DROPPER', cat='malware', sev='high',
         pat=r'(dropped.*malware|dropper.*detected|suspicious.*binary|UPX.*packed)',
         desc='Malware dropper detected'),

    # ── Network ───────────────────────────────────────────────────────────────
    dict(id='NET_SCAN',        cat='network', sev='medium',
         pat=r'(nmap|masscan|zmap|unicornscan|port scan|syn flood|SYN_FLOOD)',
         desc='Network scan detected'),
    dict(id='NET_EXFIL',       cat='network', sev='high',
         pat=r'(curl.*--upload|wget.*--post|ftp.*put.*\b\d+\s*MB|scp.*\b\d+GB)',
         desc='Potential data exfiltration'),
    dict(id='NET_DNS_TUNNEL',  cat='network', sev='high',
         pat=r'(dns.*tunnel|iodine|dnscat|dns2tcp|nstx)',
         desc='DNS tunneling detected'),
    dict(id='NET_TOR',         cat='network', sev='high',
         pat=r'(\.onion|torrc|tor browser|torsocks)',
         desc='Tor network activity'),

    # ── File ─────────────────────────────────────────────────────────────────
    dict(id='FILE_SENSITIVE',  cat='file',    sev='high',
         pat=r'(/etc/shadow|/etc/passwd|/proc/self/mem|\.aws/credentials|\.ssh/id_rsa|\.ssh/authorized_keys|SAM database)',
         desc='Sensitive file accessed'),
    dict(id='FILE_SETUID',     cat='file',    sev='high',
         pat=r'(chmod.*\+s|chmod.*4755|setuid|setgid)',
         desc='SUID/SGID bit set on file'),
    dict(id='FILE_HIDDEN',     cat='file',    sev='medium',
         pat=r'(chattr.*\+i|touch.*-t.*0001|\.\.\/\.\.|\/\.\.\/)',
         desc='File hidden or timestomped'),

    # ── System ────────────────────────────────────────────────────────────────
    dict(id='SYS_FIREWALL_OFF',cat='system',  sev='high',
         pat=r'(iptables -F|ufw disable|firewall.*stopped|netsh.*firewall.*off|Windows Firewall.*turned off)',
         desc='Firewall disabled'),
    dict(id='SYS_CRON_MOD',   cat='system',  sev='medium',
         pat=r'(crontab -e|cron.*new job|cron.*added|/etc/cron)',
         desc='Cron job modification'),
    dict(id='SYS_KERNEL_ERR',  cat='system',  sev='high',
         pat=r'(kernel: BUG|kernel: oops|kernel panic|general protection fault|Unable to handle kernel)',
         desc='Kernel error / crash'),
    dict(id='SYS_SERVICE_FAIL',cat='system',  sev='medium',
         pat=r'(systemd.*failed|service.*failed.*start|unit.*entered failed state)',
         desc='System service failed'),
    dict(id='SYS_MODULE_LOAD', cat='system',  sev='high',
         pat=r'(insmod|modprobe|loading kernel module|rootkit.*module)',
         desc='Kernel module loaded'),
    dict(id='SYS_DISK_FULL',   cat='system',  sev='medium',
         pat=r'(no space left on device|disk.*full|filesystem.*full)',
         desc='Disk full condition'),
    dict(id='SYS_LOG_CLEARED', cat='system', sev='critical',
         pat=r'(EventID=(?:1102|104)\b|audit log (?:was )?cleared|security log (?:was )?cleared|journalctl\s+--vacuum|(?:rm|unlink).*(?:/var/log|audit\.log))',
         desc='Security or system audit log cleared'),
    dict(id='SYS_SERVICE_CHANGE', cat='system', sev='high',
         pat=r'(EventID=(?:4697|7045)\b|new service (?:was )?installed|sc(?:\.exe)?\s+(?:create|config)|systemctl\s+(?:enable|disable)|service file.*(?:created|modified))',
         desc='System service installation or configuration changed'),
    dict(id='SYS_SCHEDULED_TASK_CHANGE', cat='system', sev='high',
         pat=r'(EventID=(?:4698|4699|4700|4701|4702)\b|schtasks(?:\.exe)?\s+/(?:create|change|delete)|scheduled task.*(?:created|changed|deleted)|crontab\s+-[er])',
         desc='Scheduled task or cron configuration changed'),
    dict(id='SYS_FIREWALL_CHANGE', cat='system', sev='high',
         pat=r'(New-NetFirewallRule|Remove-NetFirewallRule|Set-NetFirewallProfile|netsh\s+advfirewall|firewall rule.*(?:added|removed|modified)|iptables\s+-[AIDF]|nft\s+(?:add|delete)|ufw\s+(?:allow|deny|delete|enable|disable))',
         desc='Host firewall configuration changed'),
    dict(id='SYS_SECURITY_EXCLUSION', cat='system', sev='high',
         pat=r'(Add-MpPreference.*Exclusion|Set-MpPreference.*Exclusion|Defender exclusion.*(?:added|changed)|antivirus exclusion.*(?:added|changed))',
         desc='Security software exclusion or protection configuration changed'),
    dict(id='SYS_NETWORK_CONFIG_CHANGE', cat='system', sev='medium',
         pat=r'(netsh\s+interface|Set-DnsClientServerAddress|Set-NetIPConfiguration|nmcli\s+con(?:nection)?\s+mod|ip\s+route\s+(?:add|del)|route\s+(?:add|delete)|resolv\.conf.*(?:modified|changed)|hosts file.*(?:modified|changed))',
         desc='Network, DNS, route, proxy, or hosts configuration changed'),
    dict(id='SYS_CERTIFICATE_CHANGE', cat='system', sev='high',
         pat=r'(certutil.*(?:-addstore|-delstore)|certificate.*(?:installed|removed)|trusted root.*(?:added|removed|changed)|update-ca-certificates)',
         desc='Certificate trust store changed'),

    # ── Windows ───────────────────────────────────────────────────────────────
    dict(id='WIN_MIMIKATZ',    cat='malware', sev='critical',
         pat=r'(mimikatz|sekurlsa|lsadump|kerberoast|DCSync|Pass-the-Hash)',
         desc='Credential dumping tool detected'),
    dict(id='WIN_PSEXEC',      cat='malware', sev='high',
         pat=r'(psexec|psexesvc\.exe|ADMIN\$.*\.exe)',
         desc='PsExec lateral movement'),
    dict(id='WIN_POWERSHELL',  cat='malware', sev='high',
         pat=r'(powershell.*-[Ee]nc|-EncodedCommand|IEX\s*\(|Invoke-Expression|bypass.*execution|hidden.*window)',
         desc='Suspicious PowerShell execution'),
    dict(id='WIN_REG_PERSIST', cat='system',  sev='medium',
         pat=r'(reg\s+add.*\\Run|HKLM.*\\Run|HKCU.*\\Run|HKLM.*\\RunOnce)',
         desc='Registry persistence key added'),
    dict(id='WIN_WMIC_EXEC',   cat='system',  sev='medium',
         pat=r'wmic\s+(process|shadowcopy|os|service)\s+(call|delete|create)',
         desc='WMIC suspicious execution'),
    dict(id='WIN_LOLBIN',      cat='malware', sev='high',
         pat=r'(certutil\s+-decode|certutil\s+-urlcache|regsvr32\s+/s\s+/n|mshta\.exe|wscript\s+//[Ee])',
         desc='Living-off-the-land binary abuse'),
    dict(id='WIN_DEFENDER_OFF',cat='system',  sev='high',
         pat=r'(Set-MpPreference.*DisableRealtime|DisableAntiSpyware|DisableAntivirus|Windows Defender.*disabled)',
         desc='Windows Defender disabled'),

    # ── EDR / User Activity ───────────────────────────────────────────────────
    dict(id='EDR_PRIV_ESC',    cat='edr',     sev='critical',
         pat=r'(privilege escalation|token impersonation|UAC bypass|SeDebugPrivilege|getsystem|bypassuac)',
         desc='Privilege escalation detected'),
    dict(id='EDR_NEW_USER',    cat='edr',     sev='high',
         pat=r'(net\s+user\s+\S+\s+/add|useradd|adduser|New-LocalUser)',
         desc='New local user created'),
    dict(id='EDR_GROUP_MOD',   cat='edr',     sev='high',
         pat=r'(net\s+localgroup.*administrators|Add-LocalGroupMember.*Administrator|usermod.*sudo)',
         desc='User added to admin group'),
    dict(id='EDR_REMOTE',      cat='edr',     sev='medium',
         pat=r'(Remote Desktop.*connected|RDP.*session|TeamViewer.*session|VNC.*authenticated)',
         desc='Remote access session'),
    dict(id='PROC_LINUX_KERNEL_INJECTION', cat='edr', sev='critical',
         pat=r'type=SYSCALL.*(?:syscall=(?:101|310|311)\b|\bptrace\b|process_vm_(?:readv|writev)).*success=yes',
         desc='Linux kernel audit recorded cross-process memory access'),
    dict(id='EDR_ACCOUNT_LOCK',cat='edr',     sev='high',
         pat=r'(account.*locked|too many failed.*login|account disabled due)',
         desc='Account locked out'),

    # ── USB (log-based fallback) ───────────────────────────────────────────────
    dict(id='USB_LOG_DETECTED',cat='usb',     sev='medium',
         pat=r'(usb.*storage|usb.*drive|removable.*media|USB Mass Storage|sd[b-z]\s+added|usbstor)',
         desc='USB storage device connected (log)'),
]

_compiled = [(r, re.compile(r['pat'], re.IGNORECASE)) for r in RULES]

_IP_RE = re.compile(r'\b(\d{1,3}\.){3}\d{1,3}\b')
_ISO_TS_RE = re.compile(r'\b(\d{4}-\d{2}-\d{2}[T ][0-9:.]+(?:Z|[+-]\d{2}:?\d{2})?)\b')
_SYSLOG_TS_RE = re.compile(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b')
_LOCAL_IP_RE = re.compile(r'^(127\.|0\.0\.0\.0$|::1$|localhost$)', re.IGNORECASE)


def _is_routine_service_auth(line: str) -> bool:
    """Ignore non-interactive scheduler sessions that are not user logins."""
    text = line.lower()
    return ('cron[' in text or ' cron:' in text) and 'pam_unix(cron:session)' in text


def _parse_log_timestamp(line: str) -> str:
    """
    Preserve the original log timestamp when one is present.
    Sender drops events older than install_time, so using "now" for historical
    log lines would incorrectly upload old system logs after a fresh install.
    """
    now = datetime.now(timezone.utc)
    local_now = datetime.now().astimezone()

    iso = _ISO_TS_RE.search(line)
    if iso:
        raw = iso.group(1).replace(' ', 'T')
        if raw.endswith('Z'):
            raw = raw[:-1] + '+00:00'
        try:
            dt = datetime.fromisoformat(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except Exception:
            pass

    syslog = _SYSLOG_TS_RE.search(line)
    if syslog:
        try:
            dt = datetime.strptime(f'{local_now.year} {syslog.group(1)}', '%Y %b %d %H:%M:%S')
            dt = dt.replace(tzinfo=local_now.tzinfo).astimezone(timezone.utc)
            if dt > now + timedelta(days=1):
                dt = dt.replace(year=dt.year - 1)
            return dt.isoformat()
        except Exception:
            pass

    return now.isoformat()


def _first_match(patterns, text: str) -> str:
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            for group in m.groups():
                if group and str(group).strip() and str(group).strip() not in ('-', '(null)'):
                    return str(group).strip().strip("'\"[],")
    return ''


def _extract_username(line: str, rule_id: str = '') -> str:
    if 'EventID=' in line:
        windows_accounts = re.findall(r'Account Name:\s*([^\s\r\n]+)', line, re.IGNORECASE)
        for candidate in reversed(windows_accounts):
            clean = str(candidate).strip().strip("'\"[],")
            if clean and not clean.endswith('$') and clean.lower() not in ('system', 'anonymous', 'anonymous logon', '-'):
                return clean
    user = _first_match([
        r'Failed password for invalid user\s+([^\s]+)\s+from',
        r'Failed password for\s+([^\s]+)\s+from',
        r'Accepted \S+ for\s+([^\s]+)\s+from',
        r'Invalid user\s+([^\s]+)\s+from',
        r'session (?:opened|closed) for user\s+([^\s\)]+)',
        r'sudo:\s+([^\s:]+)\s*:',
        r'USER=([^\s;]+)',
        r'new user:\s+name=([^,\s]+)',
        r'useradd\[[^\]]+\]:\s+new user:\s+name=([^,\s]+)',
        r'userdel\[[^\]]+\]:\s+delete user\s+\'?([^,\s\']+)',
        r'usermod\[[^\]]+\]:\s+change user\s+\'?([^,\s\']+)',
        r'Account Name:\s*([^\s\r\n]+)',
        r'TargetUserName[=:]\s*([^\s,;]+)',
        r'User(?:name)?[=:]\s*([^\s,;]+)',
        r'user\s+([^\s]+)\s+(?:logged|login|authenticated)',
    ], line)
    if user and user.endswith('$'):
        return ''
    if user and user.lower() in ('system', 'anonymous', 'anonymous logon', 'account name'):
        return ''
    return user


def _extract_source_ip(line: str) -> str:
    ip = _first_match([
        r'from\s+((?:\d{1,3}\.){3}\d{1,3})\s+port',
        r'rhost=((?:\d{1,3}\.){3}\d{1,3})',
        r'Source Network Address:\s*((?:\d{1,3}\.){3}\d{1,3})',
        r'IpAddress[=:]\s*((?:\d{1,3}\.){3}\d{1,3})',
        r'Client Address:\s*((?:\d{1,3}\.){3}\d{1,3})',
    ], line)
    if ip and not _LOCAL_IP_RE.search(ip):
        return ip
    for match in _IP_RE.finditer(line):
        candidate = match.group(0)
        if not _LOCAL_IP_RE.search(candidate):
            return candidate
    return ip or ''


def _auth_method(line: str, source: str) -> str:
    text = f'{line} {source}'.lower()
    if 'windows hello' in text:
        return 'Windows Hello'
    if re.search(r'\bpin\b', text):
        return 'Windows PIN'
    if 'biometric' in text or 'fingerprint' in text or 'face recognition' in text:
        return 'Biometric'
    if 'eventid=4800' in text or 'eventid=4801' in text or re.search(r'logon type:\s*7\b', text) or 'screen unlock' in text:
        return 'Workstation Unlock'
    if 'publickey' in text or 'ssh_key' in text:
        return 'SSH Key'
    if 'sshd' in text or 'ssh' in text:
        return 'Linux SSH'
    if 'sudo' in text or 'pam_sudo' in text:
        return 'Sudo/PAM'
    if 'pam' in text:
        return 'PAM'
    if 'kerberos' in text or 'eventid=4768' in text or 'eventid=4769' in text or 'eventid=4771' in text:
        return 'Kerberos'
    if 'ntlm' in text or 'eventid=4776' in text:
        return 'NTLM'
    if 'ldap' in text:
        return 'LDAP'
    if 'rdp' in text or 'remote desktop' in text or 'eventid=1149' in text or re.search(r'logon type:\s*10', text):
        return 'RDP'
    if 'vpn' in text or 'openvpn' in text or 'wireguard' in text or 'anyconnect' in text or 'globalprotect' in text:
        return 'VPN'
    if 'mfa' in text or '2fa' in text or 'otp' in text or 'totp' in text or 'duo' in text:
        return 'MFA'
    if 'windows/security' in text or 'eventid=' in text:
        return 'Windows Logon'
    return 'Password'


def _auth_action(rule_id: str, line: str) -> str:
    text = f'{rule_id} {line}'.lower()
    canonical_rule = str(rule_id or '').upper()
    if canonical_rule == 'AUTH_SCREEN_LOCK':
        return 'screen_locked'
    if canonical_rule == 'AUTH_SCREEN_UNLOCK_SUCCESS':
        return 'screen_unlock_success'
    if canonical_rule == 'AUTH_SCREEN_UNLOCK_FAILURE':
        return 'screen_unlock_failed'
    if canonical_rule in ('AUTH_REMOTE_ACCESS', 'EDR_REMOTE'):
        if re.search(r'(?i)fail|invalid|denied|rejected|bad password|eventid=4625|eventid=4771', line):
            return 'login_failed'
        if re.search(r'(?i)accepted|success|authenticated|session opened|eventid=4624|eventid=1149', line):
            return 'remote_login'
        return 'auth_event'
    if canonical_rule == 'AUTH_ROOT_LOGIN':
        return 'privileged_login'
    if canonical_rule in ('AUTH_ADMIN_RIGHTS', 'AUTH_SUDO', 'EDR_PRIV_ESC'):
        return 'privilege_escalation'
    if canonical_rule in ('AUTH_GROUP_CHANGE', 'EDR_GROUP_MOD'):
        return 'group_membership_change'
    if canonical_rule == 'AUTH_ACCOUNT_ENABLED_DISABLED':
        return 'account_state_change'
    if canonical_rule == 'AUTH_SSH_KEY_CHANGE':
        return 'ssh_key_change'
    if canonical_rule == 'AUTH_TOKEN_ABUSE':
        return 'token_abuse'
    if canonical_rule == 'AUTH_CLOUD_IAM_ABUSE':
        return 'cloud_iam_abuse'
    if canonical_rule == 'AUTH_CREDENTIAL_STORE_ACCESS':
        return 'credential_theft'
    if canonical_rule == 'AUTH_SUCCESS':
        return 'login'
    if 'brute' in text or 'spray' in text or 'credential stuffing' in text:
        return 'brute_force'
    if 'lock' in text or 'eventid=4740' in text:
        return 'account_lockout'
    if ('mfa' in text or 'otp' in text or '2fa' in text) and ('fail' in text or 'invalid' in text or 'denied' in text or 'bypass' in text):
        return 'mfa_failure'
    if 'fail' in text or 'invalid' in text or 'denied' in text:
        return 'login_failed'
    if 'logout' in text or 'session closed' in text or 'eventid=4634' in text or 'eventid=4647' in text:
        return 'logout'
    if 'user_created' in text or 'new user' in text or 'eventid=4720' in text:
        return 'user_created'
    if 'user_deleted' in text or 'userdel' in text or 'eventid=4726' in text:
        return 'user_deleted'
    if 'user_modified' in text or 'usermod' in text or 'eventid=4738' in text:
        return 'user_modified'
    if 'group' in text or 'administrator' in text or 'sudoers' in text or 'wheel' in text:
        return 'group_membership_change'
    if 'priv' in text or 'sudo' in text or 'admin' in text or 'eventid=4672' in text:
        return 'privilege_escalation'
    if 'mfa' in text or 'otp' in text or '2fa' in text:
        return 'mfa'
    if 'remote' in text or 'rdp' in text or 'vpn' in text or 'ssh' in text:
        return 'remote_login'
    if 'success' in text or 'accepted' in text or 'eventid=4624' in text:
        return 'login'
    return 'auth_event'


def _auth_failure_reason(line: str, action: str) -> str:
    if action not in ('screen_unlock_failed', 'login_failed', 'mfa_failure', 'brute_force'):
        return ''
    reason = _first_match([
        r'Failure Reason:\s*([^\r\n]+)',
        r'Error(?: Code)?[=:]\s*([^\s,;]+)',
        r'Sub Status:\s*([^\s,;]+)',
        r'Status:\s*([^\s,;]+)',
    ], line)
    if reason:
        return reason[:240]
    if re.search(r'(?i)invalid|bad password|wrong password|unknown user', line):
        return 'Invalid credentials'
    if re.search(r'(?i)denied|failure|failed', line):
        return 'Authentication rejected by operating system'
    return 'Authentication rejected by operating system'


def _session_id(line: str) -> str:
    return _first_match([
        r'(?:Target )?Logon ID:\s*(0x[0-9a-f]+)',
        r'(?:Session|session_id)[=:]\s*([a-z0-9._:-]+)',
    ], line)


def _auth_event_id(line: str) -> Optional[int]:
    value = _first_match([r'EventID[=:]\s*(\d+)', r'Event ID[=:]\s*(\d+)'], line)
    try:
        return int(value) if value else None
    except (TypeError, ValueError):
        return None


def _source_port(line: str) -> Optional[int]:
    value = _first_match([r'from\s+(?:\d{1,3}\.){3}\d{1,3}\s+port\s+(\d+)', r'Source Port:\s*(\d+)', r'sport[=:](\d+)'], line)
    try:
        port = int(value)
        return port if 0 < port <= 65535 else None
    except (TypeError, ValueError):
        return None


def _logon_type(line: str) -> str:
    return _first_match([r'Logon Type:\s*(\d+)', r'LogonType[=:]\s*(\d+)'], line)


def _auth_domain(line: str) -> str:
    return _first_match([r'Account Domain:\s*([^\s\r\n]+)', r'TargetDomainName[=:]\s*([^\s,;]+)', r'domain[=:]\s*([^\s,;]+)'], line)


def _auth_result(action: str) -> str:
    if action in ('login_failed', 'screen_unlock_failed', 'mfa_failure', 'brute_force'):
        return 'failure'
    if action in ('login', 'remote_login', 'privileged_login', 'screen_unlock_success', 'mfa'):
        return 'success'
    return 'not_applicable'


def _auth_detection_metadata(rule_id: str, action: str) -> dict:
    rule = str(rule_id or '').upper()
    if rule in ('AUTH_BRUTE', 'TIME_AUTH_FAILURE_BURST'):
        return {'risk_score': 78, 'mitre_id': 'T1110', 'technique': 'Brute Force', 'mitre_tactic': 'Credential Access'}
    if rule == 'AUTH_PASSWORD_SPRAY':
        return {'risk_score': 88, 'mitre_id': 'T1110.003', 'technique': 'Password Spraying', 'mitre_tactic': 'Credential Access'}
    if rule == 'AUTH_FAIL':
        # One rejected authentication is evidence, not proof of brute force.
        return {'risk_score': 25}
    if rule == 'AUTH_SCREEN_UNLOCK_FAILURE':
        return {'risk_score': 35}
    if rule == 'AUTH_ROOT_LOGIN':
        return {'risk_score': 70, 'mitre_id': 'T1078.003', 'technique': 'Local Accounts', 'mitre_tactic': 'Privilege Escalation'}
    if rule == 'AUTH_ADMIN_RIGHTS':
        return {'risk_score': 45}
    if rule == 'AUTH_SUDO':
        return {'risk_score': 35}
    if rule == 'AUTH_REMOTE_ACCESS':
        return {'risk_score': 52, 'mitre_id': 'T1021', 'technique': 'Remote Services', 'mitre_tactic': 'Lateral Movement'}
    if rule in ('AUTH_USER_CREATED',):
        return {'risk_score': 68, 'mitre_id': 'T1136', 'technique': 'Create Account', 'mitre_tactic': 'Persistence'}
    if rule in ('AUTH_USER_DELETED', 'AUTH_USER_MODIFIED', 'AUTH_GROUP_CHANGE', 'AUTH_ACCOUNT_ENABLED_DISABLED'):
        return {'risk_score': 70, 'mitre_id': 'T1098', 'technique': 'Account Manipulation', 'mitre_tactic': 'Persistence'}
    if rule == 'AUTH_MFA_FAILURE':
        # A single MFA rejection does not establish MFA fatigue (T1621).
        return {'risk_score': 45}
    if rule == 'AUTH_TOKEN_ABUSE':
        return {'risk_score': 92, 'mitre_id': 'T1539', 'technique': 'Steal Web Session Cookie', 'mitre_tactic': 'Credential Access'}
    if action in ('login', 'screen_unlock_success', 'logout', 'screen_locked'):
        return {'risk_score': 10}
    return {'risk_score': 35}


def _is_screen_unlock_line(line: str) -> bool:
    return bool(re.search(
        r'(?i)(EventID=480[01]\b|EventID=462[45][\s\S]*?Logon Type:\s*7\b|screen[ _-]?(?:lock|unlock)|workstation (?:was )?(?:locked|unlocked)|pam_unix\((?:gdm-password|lightdm|xscreensaver|kscreenlocker|loginwindow):auth\))',
        line,
    ))


def _auth_raw(rule_id: str, line: str, source: str, username: str, src_ip: str) -> dict:
    method = _auth_method(line, source)
    action = _auth_action(rule_id, line)
    return {
        'auth_method': method,
        'auth_source': source,
        'auth_action': action,
        'auth_result': _auth_result(action),
        'failure_reason': _auth_failure_reason(line, action),
        'session_id': _session_id(line),
        'event_id': _auth_event_id(line),
        'source_port': _source_port(line),
        'logon_type': _logon_type(line),
        'domain': _auth_domain(line),
        'username': username,
        'user': username,
        'src_ip': src_ip,
        'source_ip': src_ip,
        'host_type': 'windows' if 'windows/' in source.lower() else 'linux' if source.startswith('/var/log/') or source.lower().startswith('linux/') else 'system',
        'log_type': 'authentication',
    }


def _capability_ids_for_rule(rule_id: str, category: str) -> list:
    """Attach canonical public capability IDs at the evidence source."""
    ids = set()
    if rule_id.startswith('AUTH_') or rule_id in ('EDR_ACCOUNT_LOCK', 'EDR_NEW_USER', 'EDR_GROUP_MOD', 'EDR_REMOTE'):
        ids.update((4, 13))
    if rule_id in ('AUTH_BRUTE', 'AUTH_ACCOUNT_LOCK'):
        ids.update((11, 22))
    if rule_id.startswith('RANSOMWARE_'):
        ids.add(27)
    if rule_id in ('WIN_POWERSHELL', 'MALWARE_DOWNLOAD', 'SHELL_REVERSE'):
        ids.add(21)
    if rule_id in ('WIN_POWERSHELL', 'WIN_WMIC_EXEC', 'WIN_LOLBIN'):
        ids.add(28)
    if rule_id in ('WIN_PSEXEC', 'EDR_REMOTE', 'AUTH_REMOTE_ACCESS'):
        ids.add(14)
    if rule_id == 'AUTH_EXPLICIT_CREDENTIALS':
        ids.add(14)
    if rule_id in ('WIN_MIMIKATZ', 'EDR_PRIV_ESC'):
        ids.add(13)
    if rule_id == 'FILE_SENSITIVE':
        ids.update((12, 13))
    if rule_id == 'NET_EXFIL':
        ids.add(12)
    if rule_id.startswith('NET_'):
        ids.add(3)
    if rule_id.startswith('SYS_') or rule_id in (
        'WIN_DEFENDER_OFF', 'WIN_REG_PERSIST', 'AUTH_USER_CREATED',
        'AUTH_USER_DELETED', 'AUTH_USER_MODIFIED', 'AUTH_GROUP_CHANGE',
        'AUTH_ADMIN_RIGHTS', 'AUTH_ACCOUNT_ENABLED_DISABLED', 'EDR_NEW_USER', 'EDR_GROUP_MOD',
    ):
        ids.add(7)
    if rule_id in ('SYS_SERVICE_FAIL', 'SYS_SERVICE_CHANGE', 'SYS_FIREWALL_OFF', 'SYS_FIREWALL_CHANGE', 'WIN_DEFENDER_OFF'):
        ids.update((7, 24))
    if rule_id in ('SYS_CRON_MOD', 'WIN_REG_PERSIST'):
        ids.update((7, 8))
    if rule_id in ('AUTH_SSH_KEY_CHANGE', 'EDR_NEW_USER', 'EDR_GROUP_MOD', 'SYS_MODULE_LOAD'):
        ids.add(8)
    if rule_id == 'WIN_REG_PERSIST':
        ids.add(6)
    if rule_id in ('SYS_KERNEL_ERR', 'SYS_MODULE_LOAD', 'PROC_LINUX_KERNEL_INJECTION'):
        ids.add(19)
    if category == 'file':
        ids.add(2)
    if category == 'usb':
        ids.add(10)
    return sorted(ids)


def _system_change_metadata(rule_id: str, line: str, file_path: str = '') -> dict:
    """Normalize log-backed configuration changes without inventing context."""
    rid = str(rule_id or '').upper()
    category = 'system_configuration'
    mitre_id = ''
    technique = ''
    risk = 45
    if rid in ('AUTH_USER_CREATED', 'AUTH_USER_DELETED', 'AUTH_USER_MODIFIED', 'EDR_NEW_USER'):
        category, risk, mitre_id, technique = 'users_groups', 68, 'T1136', 'Create Account'
    elif rid in ('AUTH_GROUP_CHANGE', 'AUTH_ADMIN_RIGHTS', 'AUTH_ACCOUNT_ENABLED_DISABLED', 'EDR_GROUP_MOD'):
        category, risk, mitre_id, technique = 'users_groups', 75, 'T1098', 'Account Manipulation'
    elif 'SERVICE' in rid:
        category, risk, mitre_id, technique = 'services', 72, 'T1543', 'Create or Modify System Process'
    elif 'SCHEDULED_TASK' in rid or 'CRON' in rid:
        category, risk, mitre_id, technique = 'scheduled_tasks', 72, 'T1053', 'Scheduled Task/Job'
    elif 'FIREWALL' in rid or 'DEFENDER' in rid or 'SECURITY_EXCLUSION' in rid:
        category, risk, mitre_id, technique = 'security_configuration', 82, 'T1562.001', 'Impair Defenses'
    elif 'LOG_CLEARED' in rid:
        category, risk, mitre_id, technique = 'audit_tampering', 90, 'T1070.001', 'Clear Windows Event Logs'
    elif 'NETWORK_CONFIG' in rid:
        category, risk = 'network_configuration', 58
    elif 'CERTIFICATE' in rid:
        category, risk, mitre_id, technique = 'certificates', 72, 'T1553.004', 'Install Root Certificate'
    elif 'MODULE' in rid or 'KERNEL' in rid:
        category, risk, mitre_id, technique = 'boot_kernel', 82, 'T1547.006', 'Kernel Modules and Extensions'
    elif 'REG_' in rid:
        category, risk, mitre_id, technique = 'registry_configuration', 68, 'T1112', 'Modify Registry'

    target = file_path
    if not target:
        match = re.search(r'(?i)(?:service|unit|task|user|group|certificate|rule)[ =:\"\']+([\w.$@\\/:-]{2,260})', line)
        target = match.group(1) if match else ''
    return {
        'system_change_category': category,
        'system_change_type': rid.lower(),
        'system_change_target': target,
        'baseline_status': 'unexpected',
        'change_source': 'os_security_log',
        'risk_score': risk,
        'confidence_score': 88 if re.search(r'EventID=\d+', line, re.I) else 72,
        'mitre_id': mitre_id or None,
        'technique': technique or None,
    }


def _outside_working_hours(when: datetime, start_hour: int, end_hour: int) -> bool:
    """Support both normal (08-20) and overnight (20-08) work windows."""
    hour = when.hour
    start_hour %= 24
    end_hour %= 24
    if start_hour == end_hour:
        return False
    if start_hour < end_hour:
        return not (start_hour <= hour < end_hour)
    return end_hour <= hour < start_hour


class RuleDetector:
    def __init__(self, sender, responder=None, config=None):
        self._sender = sender
        self._responder = responder
        self._config = config or {}
        self._auth_failures = defaultdict(lambda: deque())
        self._auth_source_failures = defaultdict(lambda: deque())
        self._time_alerted = {}
        self._time_user_hours = defaultdict(lambda: [0] * 24)
        self._time_user_samples = defaultdict(int)
        self._time_lock = threading.Lock()

    def _cfg_int(self, key, default):
        try:
            return int(self._config.get(key, default))
        except (TypeError, ValueError, AttributeError):
            return int(default)

    def _time_all_rules_bypassed(self):
        if not self._config.get('time_anomaly_bypass_active', False):
            return False
        expiry_value = self._config.get('time_anomaly_bypass_until')
        if not expiry_value:
            return False
        try:
            expiry = datetime.fromisoformat(str(expiry_value).replace('Z', '+00:00'))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            return expiry > datetime.now(timezone.utc)
        except (TypeError, ValueError):
            return False

    def _time_exception_matches(self, rule_id, line, username, src_ip, local_now):
        host = str(self._config.get('system_name') or self._config.get('hostname') or '').lower()
        process = str(_first_match([
            r'(?i)(?:process|image|executable)[=: ]+([^\s,;]+)',
            r'(?i)\b([\w.-]+\.(?:exe|ps1|bat|cmd|sh|py))\b',
        ], line) or '').lower()
        now_utc = datetime.now(timezone.utc)
        for item in self._config.get('time_anomaly_exceptions', []) or []:
            if not isinstance(item, dict):
                continue
            expires = item.get('expires_at') or item.get('expiresAt')
            if expires:
                try:
                    expiry = datetime.fromisoformat(str(expires).replace('Z', '+00:00'))
                    if expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=timezone.utc)
                    if expiry <= now_utc:
                        continue
                except (TypeError, ValueError):
                    continue
            kind = str(item.get('type') or '').lower()
            value = str(item.get('value') or '').strip().lower()
            if not value:
                continue
            if kind in ('user', 'service_account') and value == str(username or '').lower():
                return True
            if kind == 'ip' and value == str(src_ip or '').lower():
                return True
            if kind == 'host' and value == host:
                return True
            if kind == 'process' and (value == process or value in str(line or '').lower()):
                return True
            if kind == 'maintenance_window':
                match = re.fullmatch(r'([01]?\d|2[0-3]):?([0-5]\d)?-([01]?\d|2[0-3]):?([0-5]\d)?', value)
                if match:
                    start = int(match.group(1)) * 60 + int(match.group(2) or 0)
                    end = int(match.group(3)) * 60 + int(match.group(4) or 0)
                    minute = local_now.hour * 60 + local_now.minute
                    if start == end or (start < end and start <= minute < end) or (start > end and (minute >= start or minute < end)):
                        return True
        return False

    def _time_analytics(self, rule_id, line, source, username, src_ip, category='edr', severity='low'):
        if not self._config.get('time_anomaly_enabled', True) or self._time_all_rules_bypassed():
            return
        now_ts = time.time()
        action = _auth_action(rule_id, line)
        timezone_name = str(self._config.get('time_anomaly_timezone') or 'endpoint-local').strip()
        if timezone_name.lower() != 'endpoint-local' and ZoneInfo:
            try:
                local_now = datetime.now(ZoneInfo(timezone_name))
            except (KeyError, ValueError):
                local_now = datetime.now().astimezone()
        else:
            local_now = datetime.now().astimezone()
        start_hour = self._cfg_int('working_hours_start', 8) % 24
        end_hour = self._cfg_int('working_hours_end', 20) % 24
        configured_weekends = self._config.get('time_anomaly_weekend_days', [5, 6])
        try:
            weekend_days = {int(day) for day in configured_weekends}
        except (TypeError, ValueError):
            weekend_days = {5, 6}
        weekend = local_now.weekday() in weekend_days
        holiday = local_now.date().isoformat() in {str(day) for day in (self._config.get('time_anomaly_holidays', []) or [])}
        outside = _outside_working_hours(local_now, start_hour, end_hour)
        if self._time_exception_matches(rule_id, line, username, src_ip, local_now):
            return
        expected_time = f'{start_hour:02d}:00-{end_hour:02d}:00'
        actual_time = local_now.isoformat()
        base = {
            'category': 'edr', 'source': 'time_anomaly',
            'capabilityId': 22, 'capabilityIds': sorted(set([22] + _capability_ids_for_rule(rule_id, category))),
            'username': username, 'src_ip': src_ip,
            'log_source': source, 'timestamp': datetime.now(timezone.utc).isoformat(),
            'actual_time': actual_time, 'expected_time': expected_time,
            'time_window': 'Holiday' if holiday else ('Weekend' if weekend else ('Outside configured business hours' if outside else 'Configured business hours')),
        }
        if action == 'login_failed':
            window = max(30, self._cfg_int('time_auth_failure_window_seconds', 300))
            threshold = max(3, self._cfg_int('time_auth_failure_threshold', 5))
            key = (username or 'unknown', src_ip or 'unknown')
            with self._time_lock:
                samples = self._auth_failures[key]
                samples.append(now_ts)
                while samples and samples[0] < now_ts - window:
                    samples.popleft()
                count = len(samples)
                last = self._time_alerted.get(('burst', key), 0)
                should_emit = count >= threshold and now_ts - last >= window
                if should_emit:
                    self._time_alerted[('burst', key)] = now_ts
            if should_emit:
                self._sender.enqueue({
                    **base, 'rule_id': 'TIME_AUTH_FAILURE_BURST', 'severity': 'high',
                    'risk_score': min(100, 45 + count * 5),
                    'mitre_id': 'T1110', 'technique': 'Brute Force', 'mitre_tactic': 'Credential Access',
                    'auth_result': 'failure', 'auth_type': _auth_method(line, source),
                    'failure_reason': 'Repeated authentication failures exceeded the configured threshold',
                    'eventType': 'Authentication Burst', 'user_action': 'authentication_burst',
                    'description': f'{count} authentication failures in {window} seconds for {username or "unknown user"}',
                    'baseline_diff': f'{count} failures in {window} seconds', 'baseline_confidence': 100,
                    'raw': {
                        'failure_count': count, 'window_seconds': window, 'source_event': rule_id,
                        'local_hour': local_now.hour, 'weekday': local_now.weekday(),
                        'working_hours_start': start_hour, 'working_hours_end': end_hour,
                        'actual_time': actual_time, 'expected_time': expected_time,
                        'time_window': 'Authentication burst', 'baseline_confidence': 100,
                    },
                    'raw_log': line[:500],
                })
            if src_ip:
                spray_window = max(30, self._cfg_int('auth_password_spray_window_seconds', window))
                spray_users = max(3, self._cfg_int('auth_password_spray_user_threshold', 5))
                with self._time_lock:
                    samples = self._auth_source_failures[src_ip]
                    samples.append((now_ts, username or 'unknown'))
                    while samples and samples[0][0] < now_ts - spray_window:
                        samples.popleft()
                    distinct_users = {sample_user for _, sample_user in samples if sample_user != 'unknown'}
                    spray_key = ('password_spray', src_ip)
                    last_spray = self._time_alerted.get(spray_key, 0)
                    emit_spray = len(distinct_users) >= spray_users and now_ts - last_spray >= spray_window
                    if emit_spray:
                        self._time_alerted[spray_key] = now_ts
                if emit_spray:
                    self._sender.enqueue({
                        **base, 'rule_id': 'AUTH_PASSWORD_SPRAY', 'capabilityId': 4,
                        'capabilityIds': [4, 11, 13, 22], 'severity': 'critical',
                        'risk_score': min(100, 70 + len(distinct_users) * 3),
                        'mitre_id': 'T1110.003', 'technique': 'Password Spraying', 'mitre_tactic': 'Credential Access',
                        'auth_result': 'failure', 'auth_type': _auth_method(line, source),
                        'failure_reason': 'One source failed authentication across multiple distinct accounts',
                        'eventType': 'Password Spray', 'user_action': 'password_spray',
                        'description': f'Password spray from {src_ip}: {len(distinct_users)} distinct users in {spray_window} seconds',
                        'related_users': sorted(distinct_users)[:50],
                        'raw': {'source_ip': src_ip, 'distinct_user_count': len(distinct_users), 'failure_count': len(samples), 'window_seconds': spray_window},
                        'raw_log': line[:500],
                    })
            return

        weekend_detection = weekend and self._config.get('time_anomaly_weekends', True)
        if not outside and not weekend_detection and not holiday:
            return

        if action in ('login', 'remote_login'):
            baseline_key = username or 'unknown'
            with self._time_lock:
                prior_total = self._time_user_samples[baseline_key]
                prior_hour = self._time_user_hours[baseline_key][local_now.hour]
                self._time_user_samples[baseline_key] += 1
                self._time_user_hours[baseline_key][local_now.hour] += 1
            historical_frequency = round((prior_hour / prior_total) * 100, 2) if prior_total else 0.0
            minimum_samples = max(1, self._cfg_int('time_baseline_minimum_samples', 20))
            baseline_confidence = min(100, round((prior_total / minimum_samples) * 100))
            risk_score = 25 + (10 if weekend_detection else 0) + (15 if holiday else 0)
            if action == 'remote_login':
                risk_score += 10
            if re.search(r'(?i)\b(root|admin(?:istrator)?|system)\b', username or ''):
                risk_score += 15
            if prior_total >= minimum_samples and historical_frequency < 5:
                risk_score += 15
            risk_score = min(100, risk_score)
            threshold = max(0, min(100, self._cfg_int('time_anomaly_risk_threshold', 45)))
            if risk_score < threshold:
                return
            anomaly_rule = 'TIME_AFTER_HOURS_AUTH'
            event_type = 'After-hours Authentication'
            period = 'during a configured holiday' if holiday else ('during weekend' if weekend_detection else 'outside configured working hours')
            description = f'Authentication occurred {period} for {username or "unknown user"}'
        elif str(severity).lower() in ('high', 'critical'):
            historical_frequency = 0.0
            baseline_confidence = 0
            risk_score = min(100, 25 + (40 if str(severity).lower() == 'critical' else 25) + (10 if weekend_detection else 0) + (15 if holiday else 0))
            if risk_score < max(0, min(100, self._cfg_int('time_anomaly_risk_threshold', 45))):
                return
            anomaly_rule = 'TIME_OFF_HOURS_SECURITY_ACTIVITY'
            event_type = 'Suspicious Activity at Unusual Time'
            period = 'during a configured holiday' if holiday else ('during weekend' if weekend_detection else 'outside configured working hours')
            description = f'{rule_id} occurred {period}'
        else:
            return

        key = ('after_hours', anomaly_rule, rule_id, username or 'unknown', src_ip or 'unknown')
        with self._time_lock:
            last = self._time_alerted.get(key, 0)
            should_emit = now_ts - last >= max(300, self._cfg_int('time_anomaly_cooldown_seconds', 3600))
            if should_emit:
                self._time_alerted[key] = now_ts
        if should_emit:
            self._sender.enqueue({
                **base, 'rule_id': anomaly_rule,
                'severity': 'critical' if risk_score >= 81 else 'high' if risk_score >= 61 else 'medium' if risk_score >= 41 else 'low',
                'risk_score': risk_score, 'eventType': event_type,
                'user_action': 'after_hours_login' if action in ('login', 'remote_login') else 'time_anomaly',
                'description': description,
                'baseline_diff': f'Historical frequency {historical_frequency}%',
                'baseline_confidence': baseline_confidence,
                'raw': {
                    'local_hour': local_now.hour, 'weekday': local_now.weekday(),
                    'working_hours_start': start_hour, 'working_hours_end': end_hour,
                    'source_event': rule_id, 'source_category': category,
                    'actual_time': actual_time, 'expected_time': expected_time,
                    'time_window': base['time_window'], 'after_hours': outside,
                    'weekend': weekend_detection, 'holiday': holiday, 'historical_frequency': historical_frequency,
                    'baseline_confidence': baseline_confidence,
                },
                'raw_log': line[:500],
            })

    def analyze(self, line: str, source: str):
        if not line.strip():
            return
        if _is_routine_service_auth(line):
            return

        # Extract IP once per line (reused across rules)
        src_ip = _extract_source_ip(line)

        for rule, pattern in _compiled:
            if not pattern.search(line):
                continue

            # Extract file path if present
            file_path = ''
            fp_match  = re.search(r'(/[\w./\-]+\.\w+|[A-Z]:\\[\w\\.\-]+\.\w+)', line)
            if fp_match:
                file_path = fp_match.group(0)

            rule_id = rule['id']
            if _is_screen_unlock_line(line) and rule_id in ('AUTH_FAIL', 'AUTH_SUCCESS'):
                continue
            if rule_id.startswith('AUTH_SCREEN_'):
                if not self._config.get('credential_monitor_lock_screen_enabled', True):
                    continue
                enabled_rules = self._config.get('credential_enabled_rule_ids', None)
                if enabled_rules is not None and rule_id not in set(enabled_rules or []):
                    continue
            username = _extract_username(line, rule_id) if rule['cat'] == 'edr' else ''
            raw_meta = _auth_raw(rule_id, line, source, username, src_ip) if rule['cat'] == 'edr' else None

            alert: dict = {
                'rule_id':     rule['id'],
                'capabilityIds': _capability_ids_for_rule(rule['id'], rule['cat']),
                'category':    rule['cat'],
                'severity':    rule['sev'],
                'description': rule['desc'],
                'src_ip':      src_ip,
                'file_path':   file_path if file_path else None,
                'log_source':  source,
                'raw_log':     line[:500],
                'timestamp':   _parse_log_timestamp(line),
            }
            if raw_meta:
                alert['raw'] = raw_meta
                alert.update(_auth_detection_metadata(rule_id, raw_meta.get('auth_action')))
                alert['auth_type'] = raw_meta.get('auth_method')
                alert['auth_result'] = raw_meta.get('auth_result')
                alert['failure_reason'] = raw_meta.get('failure_reason') or None
                alert['session_id'] = raw_meta.get('session_id') or None
                alert['source_port'] = raw_meta.get('source_port')
                alert['logon_type'] = raw_meta.get('logon_type') or None
                alert['domain'] = raw_meta.get('domain') or None
                alert['windows_event_id'] = raw_meta.get('event_id')
                if 13 in alert['capabilityIds']:
                    alert['credential_event_type'] = raw_meta.get('auth_action') or 'authentication'
                    alert['failure_reason'] = (raw_meta.get('failure_reason') or rule['desc']) if alert['auth_result'] == 'failure' else None
                if 14 in alert['capabilityIds']:
                    alert['lateral_vector'] = raw_meta.get('auth_method') or 'Remote Authentication'
                    alert['auth_protocol'] = raw_meta.get('auth_method')
                    alert['source_host'] = src_ip
            if username:
                alert['username'] = username
            if 7 in alert['capabilityIds']:
                alert.update(_system_change_metadata(rule_id, line, file_path))
                alert['detection_reason'] = rule['desc']

            # Infer malware type from rule
            if rule['cat'] == 'malware':
                if 'RANSOMWARE' in rule_id or 'SHADOW' in rule_id:
                    alert['malware_type'] = 'Ransomware'
                elif 'MINER' in rule_id:
                    alert['malware_type'] = 'Miner'
                elif 'SHELL' in rule_id:
                    alert['malware_type'] = 'Backdoor'
                elif 'MIMIKATZ' in rule_id:
                    alert['malware_type'] = 'Credential Dumper'
                elif 'LOLBIN' in rule_id:
                    alert['malware_type'] = 'LolBin'
                else:
                    alert['malware_type'] = 'Generic'

            # Infer user_action for EDR events — used by dashboard counters
            if rule['cat'] == 'edr':
                alert['user_action'] = raw_meta.get('auth_action') if raw_meta else _auth_action(rule_id, line)
                if 'MFA_FAILURE' in rule_id:
                    alert['severity'] = 'high'
                elif 'SUCCESS' in rule_id or 'LOGOUT' in rule_id or 'MFA_SUCCESS' in rule_id:
                    alert['severity'] = 'low'
                if rule_id.startswith('AUTH_SCREEN_'):
                    alert['risk_score'] = 55 if rule_id.endswith('_FAILURE') else 15 if rule_id.endswith('_SUCCESS') else 5
                    override = (self._config.get('credential_rule_overrides', {}) or {}).get(rule_id, {})
                    if isinstance(override, dict) and override.get('severity') in ('low', 'medium', 'high', 'critical'):
                        alert['severity'] = override['severity']

            self._sender.enqueue(alert)

            # Authentication baselines need log-specific semantics. Other
            # collector events are evaluated once at the sender boundary.
            if rule['cat'] == 'edr':
                self._time_analytics(rule_id, line, source, username, src_ip, rule['cat'], alert['severity'])

            # Trigger malware responder if this is a malware alert
            if self._responder and rule['cat'] == 'malware':
                try:
                    self._responder.handle_malware_alert(alert)
                except Exception as e:
                    logger.debug('Responder error: %s', e)
