import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import api from '../../api/axios';
import { SOCKET_URL, connectSocket, io, socketOptions } from '../../api/config';
import { useAuth } from '../../context/AuthContext';

const COLORS = {
  bg: '#060d16', card: '#0b1929', card2: '#0f233a', border: '#1a3050', line: '#162942',
  text: '#e2e8f0', muted: '#8ea0b8', cyan: '#22d3ee', blue: '#38bdf8', green: '#34d399',
  yellow: '#fbbf24', orange: '#fb923c', red: '#f87171', purple: '#a78bfa',
};

const PERIODS = [
  { key: 'daily', label: '24 Hours', icon: '⏱', days: 1 },
  { key: 'weekly', label: '1 Week', icon: '📆', days: 7 },
  { key: 'monthly', label: '1 Month', icon: '🗓', days: 30 },
  { key: '90days', label: '3 Months', icon: '📊', days: 90 },
];

const DEFINITIONS = {
  4: {
    title: 'User & Authentication Monitoring',
    subtitle: 'Endpoint login activity, account changes, privileged access, remote authentication and correlated identity threats',
    categories: [['all', 'All Authentication Events'], ['successful', 'Successful Logins'], ['failed', 'Failed Logins'], ['brute_force', 'Brute Force / Password Spray'], ['privileged', 'Privileged Activity'], ['account_changes', 'Account Changes'], ['remote', 'Remote Authentication'], ['anomaly', 'Behavioral / Geo Anomalies'], ['critical', 'Critical Risk']],
    classify: row => {
      const text = `${eventText(row)} ${field(row, 'authResult', 'auth_result')} ${field(row, 'userAction', 'user_action')} ${field(row, 'authType', 'auth_type', 'authProtocol')}`.toLowerCase();
      if (severity(row) === 'critical' || Number(field(row, 'riskScore', 'risk_score')) >= 80) return 'critical';
      if (/brute.force|password.spray|credential.stuffing|authentication.burst|t1110/.test(text)) return 'brute_force';
      if (/impossible.travel|geo.anomaly|unusual.login|new.ip|new.device|account.takeover|dormant|after.hours|^time_|^geo_|^ueba_/.test(text)) return 'anomaly';
      if (/user.created|user.deleted|user.modified|account.state|group.membership|password.change|password.reset|4720|4722|4724|4725|4726|4732|4733/.test(text)) return 'account_changes';
      if (/privilege|admin.right|root.login|sudo|4672/.test(text)) return 'privileged';
      if (/remote.login|rdp|remote.desktop|ssh|vpn|kerberos|ntlm|ldap/.test(text)) return 'remote';
      if (/failure|login.failed|failed.password|invalid.user|denied|rejected/.test(text)) return 'failed';
      if (/success|login.success|accepted.password|accepted.publickey|screen.unlock.success/.test(text)) return 'successful';
      return 'other';
    },
    metrics: rows => [
      ['Total Authentication Events', rows.length, COLORS.blue],
      ['Successful Logins', count(rows, row => String(field(row, 'authResult', 'auth_result')).toLowerCase() === 'success'), COLORS.green],
      ['Failed Logins', count(rows, row => String(field(row, 'authResult', 'auth_result')).toLowerCase() === 'failure'), COLORS.red],
      ['Lockouts', count(rows, row => /account.lock|locked.out|4740/.test(eventText(row))), COLORS.orange],
      ['Brute Force / Spray', count(rows, row => DEFINITIONS[4].classify(row) === 'brute_force'), COLORS.red],
      ['Privileged Activity', count(rows, row => DEFINITIONS[4].classify(row) === 'privileged'), COLORS.purple],
      ['Affected Users', unique(rows, row => field(row, 'username', 'user', 'targetUser')), COLORS.cyan],
      ['Affected Endpoints', unique(rows, host), COLORS.yellow],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Risk Score', row => field(row, 'riskScore', 'risk_score')],
      ['User', row => field(row, 'username', 'user', 'targetUser', 'user_name')],
      ['Hostname', host], ['OS', authReportOs],
      ['Source IP', authReportSourceIp],
      ['Authentication Method', row => field(row, 'authType', 'auth_type', 'authProtocol', 'auth_protocol', 'method')], ['Result', row => field(row, 'authResult', 'auth_result', 'result')],
      ['Event / Detection', row => field(row, 'eventType', 'event_type', 'userAction', 'user_action', 'credentialEventType', 'ruleId', 'description')],
      ['Windows Event ID', row => field(row, 'windowsEventId', 'eventCode', 'eventId', 'event_id')], ['Process', row => field(row, 'processName', 'process_name')],
      ['MITRE ATT&CK', row => field(row, 'mitreId', 'mitreTechnique', 'technique')], ['Status', status],
    ],
  },
  5: {
    title: 'Memory Activity Monitoring',
    subtitle: 'Process memory, injection, credential access, fileless execution, executable pages, corruption and kernel/DLL threats',
    categories: [['all', 'All Memory Threats'], ['injection', 'Process Injection'], ['credential_theft', 'Credential Theft'], ['fileless', 'Fileless Malware'], ['executable_memory', 'RWX / Executable Memory'], ['corruption', 'Heap / Stack Corruption'], ['kernel_dll', 'Kernel / DLL Threats'], ['critical', 'Critical Risk']],
    classify: row => {
      const text = `${eventText(row)} ${field(row, 'memoryProtection', 'memory_protection')} ${field(row, 'sourceProcessName', 'source_process_name')} ${field(row, 'targetProcessName', 'target_process_name')} ${field(row, 'mitreId', 'mitreTechnique')}`.toLowerCase();
      if (severity(row) === 'critical' || Number(field(row, 'riskScore', 'risk_score')) >= 80) return 'critical';
      if (/lsass|credential.dump|minidump|mimikatz|sam.access|t1003/.test(text)) return 'credential_theft';
      if (/inject|remote.thread|hollow|thread.hijack|apc|manual.map|reflective|t1055/.test(text)) return 'injection';
      if (/fileless|in.memory.payload|reflective.pe|shellcode|powershell.memory|t1620/.test(text)) return 'fileless';
      if (/rwx|page_execute_readwrite|executable.memory|virtualalloc|virtualprotect/.test(text)) return 'executable_memory';
      if (/heap|stack|buffer.overflow|corruption|rop.chain|heap.spray|dep.bypass|aslr.bypass/.test(text)) return 'corruption';
      if (/rootkit|ssdt|dkom|kernel|driver|dll|iat.hook|eat.hook|inline.hook/.test(text)) return 'kernel_dll';
      return 'other';
    },
    metrics: rows => [
      ['Total Memory Threats', rows.length, COLORS.blue],
      ['Critical / High Alerts', count(rows, row => ['critical', 'high'].includes(severity(row))), COLORS.red],
      ['Injection Events', count(rows, row => DEFINITIONS[5].classify(row) === 'injection'), COLORS.purple],
      ['Credential Theft', count(rows, row => DEFINITIONS[5].classify(row) === 'credential_theft'), COLORS.red],
      ['Fileless Malware', count(rows, row => DEFINITIONS[5].classify(row) === 'fileless'), COLORS.orange],
      ['RWX / Executable Memory', count(rows, row => DEFINITIONS[5].classify(row) === 'executable_memory'), COLORS.yellow],
      ['Affected Processes', unique(rows, row => field(row, 'targetProcessName', 'processName', 'process_name')), COLORS.cyan],
      ['Affected Endpoints', unique(rows, host), COLORS.green],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Risk Score', row => field(row, 'riskScore', 'risk_score')],
      ['Hostname', host], ['OS', row => field(row, 'osType', 'os', 'platform')], ['User', row => field(row, 'username', 'user')],
      ['Source Process', row => field(row, 'sourceProcessName', 'source_process_name', 'parentProcessName')], ['Source PID', row => field(row, 'sourcePid', 'source_pid', 'parentPid')],
      ['Target Process', row => field(row, 'targetProcessName', 'target_process_name', 'processName')], ['Target PID', row => field(row, 'targetPid', 'target_pid', 'pid')],
      ['Event / Technique', row => field(row, 'eventType', 'injectionType', 'ruleId', 'description')],
      ['Memory Usage', row => field(row, 'processMemoryMb', 'memorySize', 'memoryUsagePercent')], ['Address', row => field(row, 'memoryAddress', 'address')],
      ['Protection', row => field(row, 'memoryProtection', 'protection')], ['Entropy', row => field(row, 'entropy')],
      ['SHA-256', row => field(row, 'sha256', 'fileHash', 'processExecutableSha256')],
      ['MITRE ATT&CK', row => field(row, 'mitreId', 'mitreTechnique', 'technique')], ['Status', status],
    ],
  },
  6: {
    title: 'Registry & System Configuration Monitoring',
    subtitle: 'Windows Registry, Linux/Solaris configuration integrity, persistence, security-control, identity, network and policy changes reported by endpoint agents',
    categories: [['all', 'All Configuration Events'], ['persistence', 'Persistence Changes'], ['security', 'Security Controls'], ['identity', 'Users / Authentication'], ['network', 'Network Configuration'], ['permissions', 'Permissions / ACL'], ['policy', 'Policy Violations'], ['critical', 'Critical Risk']],
    classify: row => {
      const text = `${eventText(row)} ${field(row, 'configurationCategory')} ${field(row, 'configurationOperation')} ${field(row, 'configurationObject', 'keyPath', 'registryKey', 'filePath')}`.toLowerCase();
      if (severity(row) === 'critical' || Number(field(row, 'riskScore')) >= 80) return 'critical';
      if (row?.configurationPolicyViolation === true) return 'policy';
      if (/permission|owner|ownership|acl|security.descriptor|suid|sgid/.test(text)) return 'permissions';
      if (/user.authentication|account|credential|lsa|winlogon|sudoers|passwd|shadow|group|pam/.test(text)) return 'identity';
      if (/network.configuration|firewall|dns|proxy|tcpip|hosts|resolv.conf|vpn|smb|rdp/.test(text)) return 'network';
      if (/security.configuration|defender|antivirus|audit|eventlog|sysmon|uac|bitlocker|applocker|selinux|apparmor/.test(text)) return 'security';
      if (/persistence|runonce|autorun|startup|image.file.execution|appinit|systemd|cron|authorized.keys|ld.preload/.test(text)) return 'persistence';
      return 'other';
    },
    metrics: rows => [
      ['Total Configuration Events', rows.length, COLORS.blue],
      ['Critical / High Changes', count(rows, row => ['critical', 'high'].includes(severity(row))), COLORS.red],
      ['Unauthorized Changes', count(rows, row => /unexpected|deviation|unauthorized/.test(String(field(row, 'configurationBaselineStatus')).toLowerCase())), COLORS.orange],
      ['Persistence Changes', count(rows, row => DEFINITIONS[6].classify(row) === 'persistence'), COLORS.purple],
      ['Security-Control Changes', count(rows, row => DEFINITIONS[6].classify(row) === 'security'), COLORS.yellow],
      ['Policy Violations', count(rows, row => row?.configurationPolicyViolation === true), COLORS.red],
      ['Affected Users', unique(rows, row => field(row, 'username', 'user', 'userName')), COLORS.cyan],
      ['Affected Endpoints', unique(rows, host), COLORS.green],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host],
      ['Platform', row => field(row, 'configurationPlatform', 'osType', 'os', 'platform')],
      ['User', row => field(row, 'username', 'user', 'userName')],
      ['Category', row => field(row, 'configurationCategory', 'category')],
      ['Operation', row => field(row, 'configurationOperation', 'operation', 'fileAction', 'eventType')],
      ['Registry Key / Configuration Path', row => field(row, 'configurationObject', 'keyPath', 'registryKey', 'sourcePath', 'filePath')],
      ['Value Name', row => field(row, 'registryValueName')],
      ['Previous Value / State', row => field(row, 'oldValue', 'previousState', 'oldHash')],
      ['New Value / State', row => field(row, 'newValue', 'newState', 'newHash')],
      ['Process', row => field(row, 'processName', 'process_name')],
      ['PID', row => field(row, 'pid', 'processId')],
      ['Parent Process', row => field(row, 'parentProcessName', 'parent_process_name')],
      ['Command Line', row => field(row, 'processCmdline', 'commandLine', 'process_cmdline', 'command_line')],
      ['Process Attribution', row => field(row, 'processAttribution')],
      ['SHA-256 / Hash', row => field(row, 'sha256', 'hash', 'newHash')],
      ['Signer / Signature', row => [field(row, 'publisher', 'processPublisher', 'signer'), field(row, 'signatureStatus', 'processSignatureStatus')].filter(value => value !== '—').join(' / ') || '—'],
      ['Baseline', row => field(row, 'configurationBaselineStatus')],
      ['Policy Violation', row => row?.configurationPolicyViolation === true ? 'Yes' : row?.configurationPolicyViolation === false ? 'No' : '—'],
      ['Risk / Confidence', row => `${field(row, 'riskScore')} / ${field(row, 'confidenceScore')}`],
      ['MITRE ATT&CK', row => field(row, 'mitreId', 'mitreTechnique', 'technique')],
      ['Detection Reason', row => field(row, 'detectionReason', 'description', 'ruleId')],
      ['Action / Status', row => `${field(row, 'actionTaken')} / ${status(row)}`],
    ],
  },
  7: {
    title: 'System Changes Monitoring',
    subtitle: 'Critical files, identities, services, scheduled tasks, security controls, network configuration, software and boot changes reported by endpoint agents',
    categories: [['all', 'All System Changes'], ['system_files', 'Critical System Files'], ['identity', 'Users / Groups'], ['services_tasks', 'Services / Tasks'], ['security_network', 'Security / Network'], ['software_boot', 'Software / Boot'], ['baseline', 'Baseline Violations'], ['critical', 'Critical Risk']],
    classify: row => {
      const text = `${eventText(row)} ${field(row, 'systemChangeCategory', 'system_change_category')} ${field(row, 'systemChangeType', 'system_change_type')} ${field(row, 'systemChangeTarget', 'system_change_target')}`.toLowerCase();
      if (severity(row) === 'critical' || Number(field(row, 'riskScore', 'risk_score')) >= 80) return 'critical';
      if (/baseline|unexpected|violation/.test(String(field(row, 'baselineStatus', 'baseline_status')).toLowerCase())) return 'baseline';
      if (/user|group|identity|account|privilege|sudo|admin/.test(text)) return 'identity';
      if (/service|systemd|scheduled.task|cron|crontab/.test(text)) return 'services_tasks';
      if (/security|defender|firewall|network|dns|proxy|remote.access|rdp|ssh|log|audit/.test(text)) return 'security_network';
      if (/software|patch|driver|kernel|boot|container|docker|kubernetes/.test(text)) return 'software_boot';
      if (/critical.system.file|system.file|system32|syswow64|\/etc\/(passwd|shadow|sudoers|hosts)/.test(text)) return 'system_files';
      return 'other';
    },
    metrics: rows => [
      ['Total System Changes', rows.length, COLORS.blue],
      ['Critical / High Changes', count(rows, row => ['critical', 'high'].includes(severity(row))), COLORS.red],
      ['Critical System Files', count(rows, row => DEFINITIONS[7].classify(row) === 'system_files'), COLORS.orange],
      ['Users / Groups', count(rows, row => DEFINITIONS[7].classify(row) === 'identity'), COLORS.purple],
      ['Services / Tasks', count(rows, row => DEFINITIONS[7].classify(row) === 'services_tasks'), COLORS.yellow],
      ['Security / Network', count(rows, row => DEFINITIONS[7].classify(row) === 'security_network'), COLORS.cyan],
      ['Baseline Violations', count(rows, row => DEFINITIONS[7].classify(row) === 'baseline'), COLORS.red],
      ['Affected Endpoints', unique(rows, host), COLORS.green],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host],
      ['OS', row => field(row, 'osType', 'os', 'platform')],
      ['User', row => field(row, 'username', 'user', 'userName')],
      ['Category', row => field(row, 'systemChangeCategory', 'system_change_category', 'category')],
      ['Change Type', row => field(row, 'systemChangeType', 'system_change_type', 'changeType', 'eventType')],
      ['Target', row => field(row, 'systemChangeTarget', 'system_change_target', 'filePath', 'keyPath', 'serviceName')],
      ['Previous State', row => field(row, 'previousState', 'previous_state', 'oldValue', 'oldInventoryItem')],
      ['New State', row => field(row, 'newState', 'new_state', 'newValue', 'inventoryItem')],
      ['Process', row => field(row, 'processName', 'process_name')],
      ['Parent Process', row => field(row, 'parentProcessName', 'parent_process_name')],
      ['Command Line', row => field(row, 'processCmdline', 'commandLine', 'process_cmdline', 'command_line')],
      ['Risk / Confidence', row => `${field(row, 'riskScore', 'risk_score')} / ${field(row, 'confidenceScore', 'confidence_score')}`],
      ['Baseline', row => field(row, 'baselineStatus', 'baseline_status')],
      ['MITRE', row => field(row, 'mitreId', 'mitreTechnique', 'technique')],
      ['Detection Reason', row => field(row, 'detectionReason', 'detection_reason', 'description', 'ruleId')],
      ['Status', status],
    ],
  },
  8: {
    title: 'Persistence Mechanism Detection',
    subtitle: 'Scheduled tasks, registry autoruns, services, WMI subscriptions, startup items, SSH keys, cron/systemd, drivers and boot persistence reported by endpoint agents',
    categories: [['all', 'All Persistence Events'], ['scheduled_tasks', 'Scheduled Tasks / Cron'], ['services', 'Services / Systemd'], ['registry_wmi', 'Registry / WMI'], ['startup_ssh', 'Startup / SSH Keys'], ['drivers_boot', 'Drivers / Boot'], ['critical', 'Critical Risk']],
    classify: row => {
      const text = `${eventText(row)} ${field(row, 'persistenceType', 'persistence_type', 'inventoryType', 'inventory_type')} ${field(row, 'persistenceLocation', 'persistence_location', 'keyPath')} ${field(row, 'persistenceAction', 'persistence_action')} ${field(row, 'mitreId', 'mitreTechnique')}`.toLowerCase();
      if (severity(row) === 'critical' || Number(field(row, 'riskScore', 'risk_score')) >= 86) return 'critical';
      if (/driver|kernel.module|bootloader|boot.config|secure.boot|\bbcd\b|\bgrub\b|t1542|t1547\.006/.test(text)) return 'drivers_boot';
      if (/registry|runonce|run.key|winlogon|appinit|com.hijack|image.file.execution|\bwmi\b|event.consumer|t1546\.003/.test(text)) return 'registry_wmi';
      if (/scheduled.task|task.scheduler|\bcron\b|crontab|systemd.timer|t1053/.test(text)) return 'scheduled_tasks';
      if (/service|systemd|launchdaemon|launchagent|t1543/.test(text)) return 'services';
      if (/startup|autorun|login.item|authorized.keys|ssh.key|browser.extension|t1098\.004|t1547/.test(text)) return 'startup_ssh';
      return 'other';
    },
    metrics: rows => [
      ['Total Persistence Events', rows.length, COLORS.blue],
      ['Critical / High Alerts', count(rows, row => ['critical', 'high'].includes(severity(row))), COLORS.red],
      ['Scheduled Tasks / Cron', count(rows, row => DEFINITIONS[8].classify(row) === 'scheduled_tasks'), COLORS.orange],
      ['Services / Systemd', count(rows, row => DEFINITIONS[8].classify(row) === 'services'), COLORS.purple],
      ['Registry / WMI', count(rows, row => DEFINITIONS[8].classify(row) === 'registry_wmi'), COLORS.yellow],
      ['Startup / SSH Keys', count(rows, row => DEFINITIONS[8].classify(row) === 'startup_ssh'), COLORS.cyan],
      ['Unique Techniques', unique(rows, row => field(row, 'mitreId', 'mitreTechnique', 'technique')), COLORS.cyan],
      ['Affected Endpoints', unique(rows, host), COLORS.green],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host],
      ['OS', row => field(row, 'osType', 'os', 'platform')],
      ['User', row => field(row, 'username', 'user', 'userName', 'accountName')],
      ['Persistence Type', row => field(row, 'persistenceType', 'persistence_type', 'inventoryType', 'inventory_type', 'eventType')],
      ['Location / Entry', persistenceLocation],
      ['Task / Service / Key', persistenceEntryName],
      ['Trigger', row => field(row, 'persistenceTrigger', 'persistence_trigger')],
      ['Action / Command', persistenceCommand],
      ['Process', row => field(row, 'processName', 'process_name')],
      ['Parent Process', row => field(row, 'parentProcessName', 'parent_process_name')],
      ['SHA-256', row => field(row, 'sha256', 'fileHash', 'newHash', 'processExecutableSha256')],
      ['Signature / Publisher', row => [field(row, 'signatureStatus', 'processSignatureStatus'), field(row, 'publisher', 'processPublisher', 'signer')].filter(value => value !== '—').join(' / ') || '—'],
      ['Risk / Confidence', row => `${field(row, 'riskScore', 'risk_score')} / ${field(row, 'confidenceScore', 'confidence_score')}`],
      ['MITRE', row => field(row, 'mitreId', 'mitreTechnique', 'technique')],
      ['Detection Reason', row => field(row, 'detectionReason', 'detection_reason', 'description', 'ruleId')],
      ['Action Taken', row => field(row, 'actionTaken', 'containmentStatus', 'recommendedAction', 'action')],
      ['Status', status],
    ],
  },
  10: {
    title: 'Device Control (USB) Monitoring',
    subtitle: 'USB connections, removable-media transfers, device policy enforcement, HID threats and malware evidence reported by endpoint agents',
    categories: [['all', 'All USB Events'], ['devices', 'Device Activity'], ['transfers', 'File Transfers'], ['policy', 'Policy Violations'], ['hid', 'HID / BadUSB'], ['malware', 'USB Malware'], ['critical', 'Critical Risk']],
    classify: row => {
      const text = `${eventText(row)} ${field(row, 'deviceType', 'device_type')} ${field(row, 'fileAction', 'file_action')} ${field(row, 'usbPolicyRuleType', 'policy_rule_type')} ${field(row, 'usbEnforcementStatus', 'enforcement_status')}`.toLowerCase();
      if (severity(row) === 'critical' || Number(field(row, 'riskScore', 'risk_score')) >= 86) return 'critical';
      if (/rubber.ducky|badusb|hid.anomaly|usb_hid/.test(text)) return 'hid';
      if (/malware|virus|trojan|yara|malicious/.test(text) || Number(field(row, 'vtDetections', 'vt_detections')) > 0) return 'malware';
      if (/usb_policy|policy.violation|enforcement.failed|write.blocked/.test(text) || field(row, 'policyName', 'policy_name') !== '—') return 'policy';
      if (/file.copied|file.read|copied.to.usb|read.from.usb|usb.transfer/.test(text)) return 'transfers';
      if (/usb_device_event|storage.mounted|driver.loaded|connected|disconnected/.test(text)) return 'devices';
      return 'other';
    },
    metrics: rows => [
      ['Total USB Events', rows.length, COLORS.blue],
      ['Device Connections', count(rows, row => /usb_device_event/.test(eventText(row).toLowerCase()) && String(field(row, 'userAction', 'user_action')).toLowerCase() === 'connected'), COLORS.cyan],
      ['Policy Violations', count(rows, row => DEFINITIONS[10].classify(row) === 'policy'), COLORS.orange],
      ['Blocked / Enforced', count(rows, row => row?.blocked === true || /blocked|enforced/.test(String(field(row, 'actionTaken', 'usbEnforcementStatus', 'enforcement_status')).toLowerCase())), COLORS.red],
      ['File Transfer Events', count(rows, row => DEFINITIONS[10].classify(row) === 'transfers'), COLORS.purple],
      ['Sensitive File Events', count(rows, row => /sensitive|confidential|restricted|secret/.test(`${eventText(row)} ${field(row, 'sensitivityType', 'sensitivity_type')}`.toLowerCase())), COLORS.yellow],
      ['HID / BadUSB Threats', count(rows, row => DEFINITIONS[10].classify(row) === 'hid'), COLORS.red],
      ['Affected Endpoints', unique(rows, host), COLORS.green],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host],
      ['User', row => field(row, 'username', 'user')],
      ['USB Event', row => field(row, 'eventType', 'userAction', 'ruleId')],
      ['Device Name', row => field(row, 'device', 'deviceName', 'device_name')],
      ['Vendor', row => field(row, 'deviceVendor', 'vendor')],
      ['Serial Number', row => field(row, 'serialNumber', 'serial_number')],
      ['VID / PID', row => `${field(row, 'usbVendorId', 'vid')} / ${field(row, 'usbProductId', 'product_id')}`],
      ['Device Type', row => field(row, 'deviceType', 'device_type')],
      ['Mount Path', row => field(row, 'mountPath', 'mount_path')],
      ['File Name', row => field(row, 'fileName', 'file_name')],
      ['Bytes Transferred', row => field(row, 'bytesTransferred', 'bytes_transferred', 'fileSize', 'file_size')],
      ['Policy', row => field(row, 'policyName', 'policy_name')],
      ['Enforcement', row => field(row, 'usbEnforcementStatus', 'enforcement_status')],
      ['Action', row => field(row, 'actionTaken', 'containmentStatus', 'action')],
      ['Risk Score', row => field(row, 'riskScore', 'risk_score')],
      ['MITRE', row => field(row, 'mitreId', 'mitre_id', 'mitreTechnique')],
      ['Status', status],
    ],
  },
  11: {
    title: 'Behavioral Analytics (UEBA)',
    subtitle: 'User, endpoint, authentication, network and data-access anomalies reported by endpoint agents and correlation rules',
    categories: [['all', 'All UEBA Events'], ['authentication', 'Authentication'], ['data_access', 'Data Access'], ['endpoint', 'Endpoint Behavior'], ['network', 'Network Behavior'], ['critical', 'Critical Risk']],
    classify: row => {
      const text = `${eventText(row)} ${field(row, 'behaviorCategory', 'behavior_category')} ${field(row, 'uebaRiskFactors', 'ueba_risk_factors')}`.toLowerCase();
      if (severity(row) === 'critical' || Number(field(row, 'riskScore', 'risk_score')) >= 90) return 'critical';
      if (/auth|login|logon|password|mfa|account|session|travel|location/.test(text)) return 'authentication';
      if (/file|download|upload|usb|exfil|data.access/.test(text)) return 'data_access';
      if (/network|dns|beacon|scan|lateral|rdp|ssh|connection/.test(text)) return 'network';
      if (/endpoint|process|powershell|cmd|bash|script|resource|cpu|memory/.test(text)) return 'endpoint';
      return 'other';
    },
    metrics: rows => [
      ['Total UEBA Events', rows.length, COLORS.blue],
      ['Critical / High Risk', count(rows, row => ['critical', 'high'].includes(severity(row))), COLORS.red],
      ['Authentication Anomalies', count(rows, row => DEFINITIONS[11].classify(row) === 'authentication'), COLORS.orange],
      ['Data Access Anomalies', count(rows, row => DEFINITIONS[11].classify(row) === 'data_access'), COLORS.purple],
      ['Endpoint Anomalies', count(rows, row => DEFINITIONS[11].classify(row) === 'endpoint'), COLORS.yellow],
      ['Network Anomalies', count(rows, row => DEFINITIONS[11].classify(row) === 'network'), COLORS.cyan],
      ['Affected Users', unique(rows, row => field(row, 'username', 'user', 'entityId', 'entity_id')), COLORS.cyan],
      ['Affected Endpoints', unique(rows, host), COLORS.green],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host],
      ['User / Entity', row => field(row, 'username', 'user', 'entityId', 'entity_id')],
      ['Behavior Category', row => field(row, 'behaviorCategory', 'behavior_category', 'eventType', 'ruleId')],
      ['Anomaly', row => field(row, 'description', 'anomalyType', 'eventType', 'ruleId')],
      ['Risk Score', row => field(row, 'riskScore', 'risk_score')],
      ['Behavior / Baseline', row => `${field(row, 'behaviorScore', 'behavior_score')} / ${field(row, 'baselineScore', 'baseline_score')}`],
      ['Peer Deviation', row => field(row, 'peerDeviationScore', 'peer_deviation_score')],
      ['Confidence', row => field(row, 'uebaConfidence', 'ueba_confidence', 'confidenceScore')],
      ['Source IP', uebaReportSourceIp],
      ['Process', uebaReportProcess],
      ['Command Line', uebaReportCommandLine],
      ['MITRE', uebaReportMitre],
      ['Status', status],
    ],
  },
  12: {
    title: 'Data Security Monitoring',
    subtitle: 'File integrity, sensitive-data access, DLP, USB, cloud, database and exfiltration evidence reported by endpoint agents',
    categories: [['all', 'All Data Events'], ['sensitive', 'Sensitive Data'], ['exfiltration', 'Exfiltration'], ['usb_cloud', 'USB / Cloud'], ['database', 'Database Exports'], ['ransomware', 'Ransomware'], ['critical', 'Critical Risk']],
    classify: row => {
      const text = `${eventText(row)} ${field(row, 'dataEventType', 'data_event_type')} ${field(row, 'dataClassification', 'data_classification', 'classification')} ${field(row, 'transferChannel', 'transfer_channel')} ${field(row, 'sensitivityType', 'sensitivity_type')}`.toLowerCase();
      if (severity(row) === 'critical' || Number(field(row, 'riskScore', 'risk_score')) >= 86) return 'critical';
      if (/ransom|encrypt|mass.rename|mass.delete|shadow.copy|backup.deletion/.test(text)) return 'ransomware';
      if (/database.export|database.dump|sql.dump|mysqldump|pg.dump|mongodump/.test(text)) return 'database';
      if (/usb|removable|cloud|google.drive|onedrive|dropbox|box|mega|icloud|s3|azure.blob/.test(text)) return 'usb_cloud';
      if (/exfil|upload|transfer|ftp|sftp|scp|https/.test(text)) return 'exfiltration';
      if (/sensitive|confidential|restricted|secret|dlp|pii|aadhaar|pan|passport|private.key/.test(text)) return 'sensitive';
      return 'other';
    },
    metrics: rows => [
      ['Total Data Events', rows.length, COLORS.blue],
      ['Critical / High Alerts', count(rows, row => ['critical', 'high'].includes(severity(row))), COLORS.red],
      ['Sensitive Data Events', count(rows, row => DEFINITIONS[12].classify(row) === 'sensitive'), COLORS.purple],
      ['Exfiltration Attempts', count(rows, row => DEFINITIONS[12].classify(row) === 'exfiltration'), COLORS.orange],
      ['USB / Cloud Transfers', count(rows, row => DEFINITIONS[12].classify(row) === 'usb_cloud'), COLORS.yellow],
      ['Database Exports', count(rows, row => DEFINITIONS[12].classify(row) === 'database'), COLORS.cyan],
      ['Affected Users', unique(rows, row => field(row, 'username', 'user', 'fileUser')), COLORS.cyan],
      ['Affected Endpoints', unique(rows, host), COLORS.green],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host],
      ['User', row => field(row, 'username', 'user', 'fileUser')],
      ['Data Event', row => field(row, 'dataEventType', 'data_event_type', 'eventType', 'ruleId')],
      ['Sensitive File Name', dataSensitiveFileName],
      ['File Path', row => field(row, 'filePath', 'file_path', 'path')],
      ['File Size', row => field(row, 'fileSize', 'file_size')],
      ['Hash', row => field(row, 'fileHash', 'file_hash', 'sha256')],
      ['Classification', dataClassificationDisplay],
      ['DLP Pattern / Count', row => `${field(row, 'dlpPattern', 'dlp_pattern')} / ${field(row, 'dlpMatchCount', 'dlp_match_count')}`],
      ['Destination / Channel', dataDestinationChannel],
      ['Protocol', row => field(row, 'transferProtocol', 'transfer_protocol', 'protocol')],
      ['Bytes Transferred', row => field(row, 'bytesTransferred', 'bytes_transferred')],
      ['Process', row => field(row, 'processName', 'process_name')],
      ['Risk / Confidence', row => `${field(row, 'riskScore', 'risk_score')} / ${field(row, 'confidenceScore', 'confidence_score')}`],
      ['MITRE', row => field(row, 'mitreId', 'mitre_id', 'mitreTechnique')],
      ['Action Executed', dataActionExecuted],
      ['Status', status],
    ],
  },
  13: {
    title: 'Credential Security Monitoring',
    subtitle: 'Authentication, lock-screen, credential-theft, privilege, session, token and cloud identity evidence reported by endpoint agents',
    categories: [['all', 'All Credential Events'], ['authentication', 'Authentication'], ['lock_screen', 'Lock-screen Activity'], ['credential_theft', 'Credential Theft'], ['privileged', 'Privileged Access'], ['tokens_cloud', 'Tokens / Cloud IAM'], ['critical', 'Critical Risk']],
    classify: row => {
      const text = `${eventText(row)} ${field(row, 'credentialEventType', 'credential_event_type')} ${field(row, 'authType', 'auth_type')} ${field(row, 'credentialTarget', 'credential_target')} ${field(row, 'tokenType', 'token_type')}`.toLowerCase();
      if (severity(row) === 'critical' || Number(field(row, 'riskScore', 'risk_score')) >= 86) return 'critical';
      if (/screen.unlock|screen.lock|workstation.lock|logon.type.?7|auth_screen_/.test(text)) return 'lock_screen';
      if (/lsass|mimikatz|credential.dump|sam.dump|secretsdump|browser.password|keychain|pass.the.hash|pass.the.ticket|golden.ticket|silver.ticket/.test(text)) return 'credential_theft';
      if (/privilege|admin|sudo|root|runas|4672/.test(text)) return 'privileged';
      if (/token|oauth|jwt|api.key|cloud.iam|azure.ad|entra|aws.iam|google.workspace|okta/.test(text)) return 'tokens_cloud';
      if (/auth|login|logon|password|mfa|kerberos|ntlm|ssh|rdp|vpn/.test(text)) return 'authentication';
      return 'other';
    },
    metrics: rows => [
      ['Total Credential Events', rows.length, COLORS.blue],
      ['Critical / High Alerts', count(rows, row => ['critical', 'high'].includes(severity(row))), COLORS.red],
      ['Failed Authentication', count(rows, row => String(field(row, 'authResult', 'auth_result')).toLowerCase() === 'failure'), COLORS.orange],
      ['Failed Screen Unlocks', count(rows, row => /screen.unlock.fail|auth_screen_unlock_failure/.test(`${eventText(row)} ${field(row, 'credentialEventType', 'credential_event_type')}`.toLowerCase())), COLORS.red],
      ['Credential Theft', count(rows, row => DEFINITIONS[13].classify(row) === 'credential_theft'), COLORS.purple],
      ['Privileged Access', count(rows, row => DEFINITIONS[13].classify(row) === 'privileged'), COLORS.yellow],
      ['Affected Users', unique(rows, row => field(row, 'username', 'user', 'userName', 'accountName')), COLORS.cyan],
      ['Affected Endpoints', unique(rows, host), COLORS.green],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host],
      ['User', row => field(row, 'username', 'user', 'userName', 'accountName')],
      ['Credential Event', row => field(row, 'credentialEventType', 'credential_event_type', 'eventType', 'ruleId')],
      ['Authentication Type', row => field(row, 'authType', 'auth_type', 'authMethod')],
      ['Result', row => field(row, 'authResult', 'auth_result')],
      ['Failure Reason', row => field(row, 'failureReason', 'failure_reason')],
      ['Session / Device', row => [field(row, 'sessionId', 'session_id'), field(row, 'deviceId', 'device_id')].filter(value => value !== '—').join(' | ') || '—'],
      ['MFA', row => field(row, 'mfaStatus', 'mfa_status')],
      ['Identity Provider', row => field(row, 'identityProvider', 'identity_provider')],
      ['Privilege', row => field(row, 'privilegeLevel', 'privilege_level')],
      ['Source IP', row => field(row, 'srcip', 'sourceIp', 'src_ip')],
      ['Process', row => field(row, 'processName', 'process_name')],
      ['Command Line', row => field(row, 'processCmdline', 'commandLine', 'process_cmdline', 'command_line')],
      ['Risk / Confidence', row => `${field(row, 'riskScore', 'risk_score')} / ${field(row, 'confidenceScore', 'confidence_score')}`],
      ['MITRE', row => field(row, 'mitreId', 'mitre_id', 'mitreTechnique')],
      ['Action', row => field(row, 'actionTaken', 'containmentStatus', 'recommendedAction', 'action')],
      ['Status', status],
    ],
  },
  14: {
    title: 'Lateral Movement Detection',
    subtitle: 'Authentication, remote-service, credential-abuse, east-west network and attack-path evidence reported by endpoint agents',
    categories: [['all', 'All Lateral Events'], ['remote_services', 'Remote Services'], ['credential_abuse', 'Credential Abuse'], ['smb', 'SMB / Admin Shares'], ['authentication', 'Authentication'], ['discovery', 'Discovery / Scanning'], ['critical', 'Critical Risk']],
    classify: row => {
      const text = `${eventText(row)} ${field(row, 'lateralVector', 'lateral_vector')} ${field(row, 'authProtocol', 'auth_protocol')} ${field(row, 'shareName', 'share_name')} ${field(row, 'sessionState', 'session_state')}`.toLowerCase();
      if (severity(row) === 'critical' || Number(field(row, 'riskScore', 'risk_score')) >= 86) return 'critical';
      if (/pass.the.hash|pass.the.ticket|golden.ticket|silver.ticket|overpass|credential|lsass|mimikatz|token.(?:theft|impersonation)|rubeus|lazagne/.test(text)) return 'credential_abuse';
      if (/admin\$|ipc\$|netlogon|sysvol|hidden.share|share.enumer|\bsmb\b|port.445/.test(text)) return 'smb';
      if (/rdp|ssh|vnc|psexec|paexec|\bwmi\b|winrm|remote.(?:service|registry|desktop|powershell)|scheduled.task|\brpc\b/.test(text)) return 'remote_services';
      if (/auth|login|logon|kerberos|ntlm|service.account|domain.account|brute.force|failed.login/.test(text)) return 'authentication';
      if (/discover|enumerat|scan|bloodhound|sharphound|crackmapexec|netexec|adfind/.test(text)) return 'discovery';
      return 'other';
    },
    metrics: rows => [
      ['Total Lateral Events', rows.length, COLORS.blue],
      ['Critical / High Alerts', count(rows, row => ['critical', 'high'].includes(severity(row))), COLORS.red],
      ['Remote Service Events', count(rows, row => DEFINITIONS[14].classify(row) === 'remote_services'), COLORS.orange],
      ['Credential Abuse', count(rows, row => DEFINITIONS[14].classify(row) === 'credential_abuse'), COLORS.purple],
      ['SMB / Admin Shares', count(rows, row => DEFINITIONS[14].classify(row) === 'smb'), COLORS.yellow],
      ['Authentication Events', count(rows, row => DEFINITIONS[14].classify(row) === 'authentication'), COLORS.cyan],
      ['Attack Paths', unique(rows, row => field(row, 'attackPathId', 'attack_path_id')), COLORS.green],
      ['Affected Endpoints', unique(rows, row => field(row, 'destinationHost', 'destination_host', 'destip', 'dstIp')), COLORS.cyan],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host],
      ['User', row => field(row, 'username', 'user', 'userName', 'accountName')],
      ['Lateral Vector', row => field(row, 'lateralVector', 'lateral_vector', 'eventType', 'ruleId')],
      ['Source Host', row => field(row, 'sourceHost', 'source_host', 'srcHost')],
      ['Destination Host', row => field(row, 'destinationHost', 'destination_host', 'dstHost')],
      ['Source IP / Port', row => `${field(row, 'srcip', 'sourceIp', 'src_ip')}${field(row, 'sourcePort', 'srcPort', 'source_port') !== '—' ? `:${field(row, 'sourcePort', 'srcPort', 'source_port')}` : ''}`],
      ['Destination IP / Port', row => `${field(row, 'destip', 'destinationIp', 'dstIp', 'dest_ip')}${field(row, 'destPort', 'destinationPort', 'dest_port') !== '—' ? `:${field(row, 'destPort', 'destinationPort', 'dest_port')}` : ''}`],
      ['Auth Protocol', row => field(row, 'authProtocol', 'auth_protocol')],
      ['Share / Session', row => [field(row, 'shareName', 'share_name'), field(row, 'sessionState', 'session_state')].filter(value => value !== '—').join(' | ') || '—'],
      ['Process', row => field(row, 'processName', 'process_name')],
      ['Parent Process', row => field(row, 'parentProcessName', 'parent_process_name')],
      ['Command Line', row => field(row, 'processCmdline', 'commandLine', 'process_cmdline', 'command_line')],
      ['Risk / Confidence', row => `${field(row, 'riskScore', 'risk_score')} / ${field(row, 'confidenceScore', 'confidence_score')}`],
      ['MITRE', row => field(row, 'mitreId', 'mitre_id', 'mitreTechnique')],
      ['Action', row => field(row, 'actionTaken', 'containmentStatus', 'recommendedAction', 'action')],
      ['Status', status],
    ],
  },
  15: {
    title: 'Email Threat Monitoring',
    subtitle: 'Webmail, mail-client, attachment, URL, authentication and mailbox-threat evidence reported by endpoint agents and mail gateways',
    categories: [['all', 'All Email Events'], ['phishing', 'Phishing / BEC'], ['attachments', 'Attachments / Payloads'], ['urls', 'Suspicious URLs'], ['authentication', 'SPF / DKIM / DMARC'], ['mailbox', 'Mailbox Activity'], ['blocked', 'Blocked / Quarantined']],
    classify: row => {
      const text = emailText(row);
      if (row?.blocked === true || row?.quarantined === true || /block|quarantin|reject|delete/.test(`${field(row, 'actionTaken', 'containmentStatus', 'action')} ${text}`)) return 'blocked';
      if (/spf|dkim|dmarc|spoof|sender.reputation|domain.reputation/.test(text)) return 'authentication';
      if (/mailbox|oauth|forward.rule|auto.delete|delegat|bulk.forward|bulk.delete|impossible.travel|password.reset|suspicious.token/.test(text)) return 'mailbox';
      if (field(row, 'fileName', 'filename') !== '—' || /attachment|macro|payload|archive|\.zip|\.rar|\.iso|\.lnk/.test(text)) return 'attachments';
      if (field(row, 'url') !== '—' || /suspicious.url|email.link|redirect|typosquat|fake.login/.test(text)) return 'urls';
      if (/phish|credential|business.email.compromise|\bbec\b|wire.fraud|spam/.test(text)) return 'phishing';
      return 'other';
    },
    metrics: rows => [
      ['Total Email Events', rows.length, COLORS.blue],
      ['Critical / High Threats', count(rows, row => ['critical', 'high'].includes(severity(row))), COLORS.red],
      ['Phishing / BEC', count(rows, row => DEFINITIONS[15].classify(row) === 'phishing'), COLORS.orange],
      ['Attachment Threats', count(rows, row => DEFINITIONS[15].classify(row) === 'attachments'), COLORS.purple],
      ['Suspicious URLs', count(rows, row => DEFINITIONS[15].classify(row) === 'urls'), COLORS.yellow],
      ['Authentication Failures', count(rows, row => /spf.*fail|dkim.*fail|dmarc.*(?:fail|reject)|spoof/.test(emailText(row))), COLORS.red],
      ['Blocked / Quarantined', count(rows, row => DEFINITIONS[15].classify(row) === 'blocked'), COLORS.green],
      ['Affected Endpoints', unique(rows, host), COLORS.cyan],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host],
      ['User', row => field(row, 'username', 'user', 'userName')],
      ['Threat Type', row => field(row, 'threatCategory', 'eventType', 'ruleId')],
      ['Domain / URL', row => field(row, 'url', 'domain')],
      ['Attachment', row => field(row, 'fileName', 'filename', 'filePath')],
      ['SHA-256', row => field(row, 'sha256', 'fileHash')],
      ['Risk Score', row => field(row, 'riskScore', 'risk_score')],
      ['Action', row => field(row, 'actionTaken', 'containmentStatus', 'action')],
      ['MITRE ATT&CK', emailMitre], ['Status', status],
    ],
  },
  16: {
    title: 'Insider Threat Detection',
    subtitle: 'User behavior, privilege abuse, sensitive-data access and exfiltration evidence reported by endpoint agents',
    categories: [['all', 'All Insider Events'], ['exfiltration', 'Data Exfiltration'], ['privilege', 'Privilege Abuse'], ['after_hours', 'After-Hours Activity'], ['removable', 'USB / Removable Media'], ['sensitive', 'Sensitive Data Access'], ['critical', 'Critical Risk']],
    classify: row => {
      const text = eventText(row);
      if (severity(row) === 'critical' || Number(field(row, 'riskScore', 'risk_score', 'userRiskScore')) >= 86) return 'critical';
      if (/usb|removable|external.device/.test(text)) return 'removable';
      if (/exfil|upload|cloud|dropbox|google.drive|sftp|ftp|scp|archive.staging/.test(text)) return 'exfiltration';
      if (/privilege|admin.abuse|sudo|elevation|unauthorized.admin/.test(text)) return 'privilege';
      if (/after.hours|off.hours|late.night|weekend|unusual.time/.test(text)) return 'after_hours';
      if (/sensitive.file|confidential|restricted.data|mass.file|data.access/.test(text)) return 'sensitive';
      return 'other';
    },
    metrics: rows => [
      ['Total Insider Events', rows.length, COLORS.blue],
      ['Critical Risk Events', count(rows, row => severity(row) === 'critical' || Number(field(row, 'riskScore', 'risk_score', 'userRiskScore')) >= 86), COLORS.red],
      ['High Risk Events', count(rows, row => severity(row) === 'high' || (Number(field(row, 'riskScore', 'risk_score', 'userRiskScore')) >= 61 && Number(field(row, 'riskScore', 'risk_score', 'userRiskScore')) < 86)), COLORS.orange],
      ['Exfiltration Signals', count(rows, row => DEFINITIONS[16].classify(row) === 'exfiltration'), COLORS.red],
      ['Privilege Abuse', count(rows, row => DEFINITIONS[16].classify(row) === 'privilege'), COLORS.purple],
      ['After-Hours Activity', count(rows, row => DEFINITIONS[16].classify(row) === 'after_hours'), COLORS.yellow],
      ['Affected Users', unique(rows, row => field(row, 'username', 'user', 'userName', 'accountName')), COLORS.cyan],
      ['Affected Endpoints', unique(rows, host), COLORS.green],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host],
      ['User', row => field(row, 'username', 'user', 'userName', 'accountName')],
      ['Department', row => field(row, 'departmentName', 'department', 'dept')],
      ['Signal Type', row => field(row, 'signalType', 'eventType', 'activityType', 'ruleId')],
      ['Risk Score', row => field(row, 'riskScore', 'risk_score', 'userRiskScore')],
      ['Action / Rule', row => field(row, 'action', 'ruleId', 'detectionRuleId')],
      ['Source IP', row => field(row, 'srcip', 'sourceIp', 'src_ip', 'ip')],
      ['Destination', row => field(row, 'destination', 'domain', 'url', 'destip', 'dstIp')],
      ['File / Resource', row => field(row, 'filePath', 'fileName', 'resource')],
      ['Bytes Transferred', row => field(row, 'bytesTransferred', 'bytes', 'transferBytes')],
      ['Process', row => field(row, 'processName', 'process_name')],
      ['Command Line', row => field(row, 'commandLine', 'command_line', 'processCmdline')],
      ['MITRE', row => field(row, 'mitreId', 'mitre_id', 'mitreTechnique')], ['Status', status],
    ],
  },
  17: {
    title: 'Patch & Vulnerability Monitoring',
    subtitle: 'Agent-reported installed software, installed patches, pending updates and vulnerability findings',
    categories: [['all', 'All Patch Events'], ['pending', 'Pending Updates'], ['installed', 'Installed Patches / Software'], ['health', 'Collector Health'], ['critical', 'Critical Findings'], ['failures', 'Patch Failures']],
    classify: row => {
      const inventoryType = String(field(row, 'inventoryType', 'inventory_type')).toLowerCase();
      const text = eventText(row);
      if (severity(row) === 'critical') return 'critical';
      if (/fail|error|rollback/.test(text)) return 'failures';
      if (inventoryType === 'pending_updates' || /missing|pending|unpatched|available.update/.test(text)) return 'pending';
      if (['installed_patches', 'installed_software'].includes(inventoryType) || /installed.patch|software.inventory/.test(text)) return 'installed';
      if (/sensor.health|collector.health/.test(text)) return 'health';
      return 'other';
    },
    metrics: rows => [
      ['Total Patch Events', rows.length, COLORS.blue],
      ['Pending Updates', inventoryItemCount(rows, 'pending_updates'), COLORS.orange],
      ['Installed Patches', inventoryItemCount(rows, 'installed_patches'), COLORS.green],
      ['Software Inventory', inventoryItemCount(rows, 'installed_software'), COLORS.cyan],
      ['Critical Findings', count(rows, row => severity(row) === 'critical'), COLORS.red],
      ['Patch Failures', count(rows, row => DEFINITIONS[17].classify(row) === 'failures'), COLORS.red],
      ['Inventory Snapshots', unique(rows, row => field(row, 'inventorySnapshotId', 'inventory_snapshot_id')), COLORS.purple],
      ['Affected Endpoints', unique(rows, host), COLORS.yellow],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host], ['OS', row => field(row, 'osName', 'os_name', 'osType', 'os', 'platform')],
      ['Inventory Type', row => field(row, 'inventoryType', 'inventory_type')], ['Item Count', row => inventoryRowCount(row)],
      ['Package / KB', row => inventoryItemNames(row)], ['Snapshot', row => field(row, 'inventorySnapshotId', 'inventory_snapshot_id')],
      ['Batch', row => `${field(row, 'inventoryBatchIndex', 'inventory_batch_index')} / ${field(row, 'inventoryBatchCount', 'inventory_batch_count')}`],
      ['Detection', row => field(row, 'ruleId', 'detectionRuleId', 'description')], ['Risk Score', row => field(row, 'riskScore', 'cvss', 'cvssScore')],
      ['CVE', row => field(row, 'cve', 'cveId', 'cve_id')], ['Status', status],
    ],
  },
  18: {
    title: 'Sandbox Analysis',
    subtitle: 'Agent-collected suspicious files, YARA matches, threat-intelligence verdicts and containment evidence',
    categories: [['all', 'All Sandbox Events'], ['malware', 'Malware / YARA'], ['ransomware', 'Ransomware'], ['credentials', 'Credential Theft'], ['quarantined', 'Quarantined Files'], ['intel', 'Threat Intelligence Matches']],
    classify: row => {
      const text = eventText(row);
      if (row?.quarantined === true || /quarantin/.test(text)) return 'quarantined';
      if (/ransomware|wanna|ryuk/.test(`${field(row, 'malwareType', 'malwareFamily')} ${text}`.toLowerCase())) return 'ransomware';
      if (/credential|mimikatz|lsass/.test(`${field(row, 'malwareType', 'malwareFamily')} ${text}`.toLowerCase())) return 'credentials';
      if (row?.iocMatched === true || row?.threatIntelMatch === true || /virustotal|threat.intel|known.malicious/.test(text)) return 'intel';
      if (/yara|malware|trojan|backdoor|dropper|loader|rootkit|miner|worm/.test(`${field(row, 'malwareType', 'malwareFamily')} ${text}`.toLowerCase())) return 'malware';
      return 'other';
    },
    metrics: rows => [
      ['Total Sandbox Events', rows.length, COLORS.blue],
      ['Critical Alerts', count(rows, row => severity(row) === 'critical'), COLORS.red],
      ['Malware / YARA Matches', count(rows, row => DEFINITIONS[18].classify(row) === 'malware'), COLORS.orange],
      ['Quarantined Files', count(rows, row => row?.quarantined === true || /quarantin/.test(eventText(row))), COLORS.red],
      ['Ransomware Signals', count(rows, row => DEFINITIONS[18].classify(row) === 'ransomware'), COLORS.purple],
      ['Threat Intel Matches', count(rows, row => row?.iocMatched === true || row?.threatIntelMatch === true || /malicious|suspicious/.test(String(field(row, 'vtVerdict', 'reputation')).toLowerCase())), COLORS.yellow],
      ['Unique Samples', unique(rows, row => field(row, 'sha256', 'fileHash')), COLORS.cyan],
      ['Affected Endpoints', unique(rows, host), COLORS.green],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host], ['User', row => field(row, 'fileUser', 'username', 'user', 'userName')],
      ['Filename', row => field(row, 'fileName', 'filename', 'sampleName')], ['File Path', row => field(row, 'filePath')],
      ['SHA-256', row => field(row, 'sha256', 'fileHash')], ['MD5', row => field(row, 'md5', 'fileHashMd5')],
      ['Classification', row => field(row, 'malwareType', 'malwareFamily')], ['YARA Rules', row => field(row, 'yaraRules')],
      ['VT Verdict', row => field(row, 'vtVerdict', 'reputation')], ['VT Detection Ratio', row => field(row, 'vtDetectionRatio')],
      ['Detection', row => field(row, 'ruleId', 'detectionRuleId', 'description')], ['Risk Score', row => field(row, 'riskScore', 'vtScore')],
      ['Action', row => field(row, 'actionTaken', 'containmentStatus')], ['Status', status],
    ],
  },
  19: {
    title: 'Kernel-Level Monitoring',
    subtitle: 'Agent-reported drivers, kernel modules, integrity posture and kernel security detections',
    categories: [['all', 'All Kernel Events'], ['drivers', 'Drivers / Modules'], ['rootkits', 'Rootkit / Hidden Objects'], ['syscalls', 'Syscall / Kernel Hooks'], ['memory', 'Kernel Memory'], ['privilege', 'Privilege Escalation'], ['integrity', 'Boot / Code Integrity']],
    classify: row => {
      const text = eventText(row);
      if (/rootkit|hidden.process|hidden.module|hidden.driver|dkom/.test(text)) return 'rootkits';
      if (/sys.?call|ssdt|kernel.hook|kprobe|callback/.test(text)) return 'syscalls';
      if (/kernel.memory|rwx|shellcode|injection|corruption/.test(text)) return 'memory';
      if (/privilege|token|sedebug|seload|uac|byovd/.test(text)) return 'privilege';
      if (/secure.boot|code.integrity|patchguard|test.sign|lockdown|signature.enforce/.test(text)) return 'integrity';
      if (/driver|kernel.module|\blkm\b/.test(text)) return 'drivers';
      return 'other';
    },
    metrics: rows => [
      ['Total Kernel Events', rows.length, COLORS.blue],
      ['Critical Alerts', count(rows, row => severity(row) === 'critical'), COLORS.red],
      ['Driver / Module Events', count(rows, row => DEFINITIONS[19].classify(row) === 'drivers'), COLORS.cyan],
      ['Rootkit Signals', count(rows, row => DEFINITIONS[19].classify(row) === 'rootkits'), COLORS.red],
      ['Syscall / Hook Events', count(rows, row => DEFINITIONS[19].classify(row) === 'syscalls'), COLORS.orange],
      ['Kernel Memory Events', count(rows, row => DEFINITIONS[19].classify(row) === 'memory'), COLORS.purple],
      ['Privilege Escalations', count(rows, row => DEFINITIONS[19].classify(row) === 'privilege'), COLORS.yellow],
      ['Affected Endpoints', unique(rows, host), COLORS.green],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host], ['User', row => field(row, 'username', 'user', 'userName')],
      ['Event Type', row => field(row, 'kernelEventType', 'eventType', 'ruleId')], ['Category', row => field(row, 'kernelCategory', 'subCategory', 'category')],
      ['Driver / Module', row => field(row, 'driverName', 'moduleName', 'fileName')], ['Path', row => field(row, 'driverPath', 'modulePath', 'filePath')],
      ['SHA-256', row => field(row, 'sha256', 'fileHash')], ['Signature', row => field(row, 'signatureStatus', 'moduleSignature')],
      ['Publisher', row => field(row, 'publisher')], ['PID', row => field(row, 'pid', 'processId')],
      ['Detection', row => field(row, 'description', 'detectionReasons')], ['Risk Score', row => field(row, 'riskScore')],
      ['MITRE', row => field(row, 'mitreId', 'mitreTechnique')], ['Status', status],
    ],
  },
  20: {
    title: 'API Call Monitoring',
    subtitle: 'Agent, reverse-proxy and WAF API traffic with authentication, performance and attack evidence',
    categories: [['all', 'All API Events'], ['attacks', 'API Attacks'], ['authentication', 'Authentication'], ['performance', 'Performance / Backend'], ['rate_limit', 'Rate Limiting'], ['payload', 'Payload Security'], ['blocked', 'Blocked Requests']],
    classify: row => {
      const text = eventText(row);
      if (field(row, 'blocked') === true || /block|deny|drop/.test(text)) return 'blocked';
      if (/rate.limit|rate.abuse|http.flood|429/.test(text)) return 'rate_limit';
      if (/authentication|api.key|jwt|oauth|bearer|token|unauthori[sz]ed|forbidden|credential|brute.force/.test(text)) return 'authentication';
      if (/latency|slow|timeout|backend|service.down|5\d\d/.test(text)) return 'performance';
      if (/payload|pii|credit.card|base64|json|xml|data.leak/.test(text)) return 'payload';
      if (/sql.injection|sqli|xss|command.injection|rce|xxe|ssrf|path.traversal|file.inclusion|attack/.test(text)) return 'attacks';
      return 'other';
    },
    metrics: rows => [
      ['Total API Calls', rows.length, COLORS.blue],
      ['Successful Calls', count(rows, row => Number(field(row, 'statusCode', 'responseCode')) >= 200 && Number(field(row, 'statusCode', 'responseCode')) < 400), COLORS.green],
      ['Failed Calls', count(rows, row => Number(field(row, 'statusCode', 'responseCode')) >= 400), COLORS.orange],
      ['WAF Blocked', count(rows, row => field(row, 'blocked') === true || /block|deny|drop/.test(eventText(row))), COLORS.red],
      ['Critical Threats', count(rows, row => severity(row) === 'critical'), COLORS.red],
      ['Active Endpoints', unique(rows, row => field(row, 'requestPath', 'url', 'uri')), COLORS.cyan],
      ['Source IPs', unique(rows, row => field(row, 'sourceIp', 'clientIp', 'srcip')), COLORS.purple],
      ['Affected Systems', unique(rows, host), COLORS.yellow],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host],
      ['Method', row => field(row, 'method', 'httpMethod')], ['Endpoint', row => field(row, 'requestPath', 'url', 'uri')],
      ['Status Code', row => field(row, 'statusCode', 'responseCode')], ['Latency (ms)', row => field(row, 'responseTimeMs', 'responseTime', 'latencyMs')],
      ['Request Size', row => field(row, 'requestSize')], ['Response Size', row => field(row, 'responseSize')],
      ['Source IP', row => field(row, 'sourceIp', 'clientIp', 'srcip')], ['Country', row => field(row, 'country', 'geoCountry')],
      ['WAF Provider', row => field(row, 'wafProvider', 'provider')], ['WAF Rule', row => field(row, 'wafRuleId', 'ruleId')],
      ['Attack / Detection', row => field(row, 'attackType', 'description')], ['Risk Score', row => field(row, 'riskScore')], ['Action', row => field(row, 'action', 'actionTaken', 'status')],
    ],
  },
  21: {
    title: 'Script Execution Monitoring',
    subtitle: 'PowerShell, command shell, Python, JavaScript and Unix shell execution with behavioral detections and response evidence',
    categories: [['all', 'All Script Events'], ['powershell', 'PowerShell'], ['shell', 'CMD / Unix Shell'], ['encoded', 'Encoded / Obfuscated'], ['download', 'Download & Execute'], ['persistence', 'Persistence'], ['remote', 'Remote Execution']],
    classify: row => {
      const text = eventText(row);
      if (/encoded|obfuscat|base64|invoke.expression|\biex\b/.test(text) || Number(field(row, 'obfuscationScore', 'obfuscation_score')) > 0) return 'encoded';
      if (/download|invoke.webrequest|downloadstring|downloadfile|bits|\bcurl\b|\bwget\b/.test(text)) return 'download';
      if (/persistence|scheduled.task|schtasks|crontab|systemctl.enable|new.service/.test(text)) return 'persistence';
      if (/remote.execution|lateral|psexec|winrs|invoke.command|enter.pssession|\bssh\b/.test(text)) return 'remote';
      if (/powershell|pwsh|\.ps1\b/.test(text)) return 'powershell';
      if (/cmd\.exe|\.bat\b|\.cmd\b|unix.shell|\bbash\b|\bzsh\b|\bdash\b|\/bin\/sh|\.sh\b/.test(text)) return 'shell';
      return 'other';
    },
    metrics: rows => [
      ['Total Script Events', rows.length, COLORS.blue],
      ['Critical Alerts', count(rows, row => severity(row) === 'critical'), COLORS.red],
      ['Encoded / Obfuscated', count(rows, row => DEFINITIONS[21].classify(row) === 'encoded'), COLORS.orange],
      ['Download & Execute', count(rows, row => DEFINITIONS[21].classify(row) === 'download'), COLORS.red],
      ['PowerShell Events', count(rows, row => /powershell|pwsh|\.ps1\b/.test(eventText(row))), COLORS.cyan],
      ['Unix / CMD Shell', count(rows, row => /cmd\.exe|\.bat\b|\.cmd\b|unix.shell|\bbash\b|\bzsh\b|\bdash\b|\/bin\/sh|\.sh\b/.test(eventText(row))), COLORS.purple],
      ['Affected Users', unique(rows, row => field(row, 'username', 'user', 'userName')), COLORS.yellow],
      ['Affected Endpoints', unique(rows, host), COLORS.green],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host], ['User', row => field(row, 'username', 'user', 'userName')],
      ['Interpreter', row => field(row, 'interpreter', 'processName', 'process_name')], ['Script', row => field(row, 'scriptName', 'script_name', 'fileName', 'file_name')],
      ['Script Path', row => field(row, 'scriptPath', 'script_path', 'filePath', 'file_path')], ['SHA-256', row => field(row, 'scriptHash', 'script_hash', 'fileHash', 'sha256')],
      ['Command Line', row => field(row, 'commandLine', 'command_line', 'processCmdline', 'process_cmdline', 'cmdline')], ['Parent Process', row => field(row, 'parentProcessName', 'parent_process_name')],
      ['Detection', row => field(row, 'ruleId', 'detectionRuleId', 'detectionReasons', 'detection_reasons')], ['Obfuscation Score', row => field(row, 'obfuscationScore', 'obfuscation_score')],
      ['Risk Score', row => field(row, 'riskScore', 'risk_score')], ['MITRE', row => field(row, 'mitreId', 'mitre_id', 'mitreTechnique')], ['Status', status],
    ],
  },
  22: {
    title: 'Time-Based Anomaly Detection',
    subtitle: 'After-hours activity, weekend access, behavioral time deviations and correlated security events',
    categories: [['all', 'All Time Anomalies'], ['after_hours', 'After-Hours Activity'], ['weekend', 'Weekend Activity'], ['authentication', 'Authentication'], ['process', 'Process / Script'], ['file', 'File Activity'], ['network', 'Network Activity'], ['security', 'Security Changes']],
    classify: row => {
      const text = eventText(row);
      if (field(row, 'weekend') === true || /weekend/.test(text)) return 'weekend';
      if (/auth|login|rdp|ssh|vpn|password|mfa/.test(text)) return 'authentication';
      if (/process|powershell|script|command|lolbin|scheduled.task|cron/.test(text)) return 'process';
      if (/file|encrypt|delet|rename|backup/.test(text)) return 'file';
      if (/network|dns|upload|download|transfer|connection/.test(text)) return 'network';
      if (/privilege|policy|firewall|antivirus|edr|security|service/.test(text)) return 'security';
      if (field(row, 'afterHours', 'after_hours') === true || /after.hours|off.hours|late.night|odd.hours|unusual.time/.test(text)) return 'after_hours';
      return 'other';
    },
    metrics: rows => [
      ['Total Time Anomalies', rows.length, COLORS.blue],
      ['Critical Alerts', count(rows, row => severity(row) === 'critical'), COLORS.red],
      ['After-Hours Events', count(rows, row => field(row, 'afterHours', 'after_hours') === true || /after.hours|off.hours|late.night|odd.hours/.test(eventText(row))), COLORS.orange],
      ['Weekend Events', count(rows, row => field(row, 'weekend') === true || /weekend/.test(eventText(row))), COLORS.purple],
      ['Authentication Events', count(rows, row => /auth|login|rdp|ssh|vpn|password|mfa/.test(eventText(row))), COLORS.yellow],
      ['Baseline Deviations', count(rows, row => field(row, 'baselineDiff', 'baseline_diff') !== '—'), COLORS.cyan],
      ['Affected Users', unique(rows, row => field(row, 'username', 'user', 'userName')), COLORS.green],
      ['Affected Endpoints', unique(rows, host), COLORS.cyan],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host], ['User', row => field(row, 'username', 'user', 'userName')],
      ['Detection', row => field(row, 'anomalyType', 'eventType', 'detectionRuleId', 'ruleId')],
      ['Actual Time', row => field(row, 'actualTime', 'actual_time')], ['Expected Time', row => field(row, 'expectedTime', 'expected_time')],
      ['Time Window', row => field(row, 'timeWindow', 'time_window')], ['Baseline Deviation', row => field(row, 'baselineDiff', 'baseline_diff')],
      ['Baseline Confidence', row => field(row, 'baselineConfidence', 'baseline_confidence')],
      ['Process', row => field(row, 'processName', 'process_name')], ['Source IP', row => field(row, 'srcip', 'sourceIp', 'src_ip')],
      ['Risk Score', row => field(row, 'riskScore', 'risk_score')], ['MITRE', row => field(row, 'mitreId', 'mitre_id', 'mitreTechnique')], ['Status', status],
    ],
  },
  23: {
    title: 'Geolocation Anomaly Detection',
    subtitle: 'Device GPS, Geo-IP, allowed-radius violations, impossible travel and privacy-network activity',
    categories: [['all', 'All Geo Events'], ['location', 'Location / Radius'], ['impossible', 'Impossible Travel'], ['privacy', 'VPN / Proxy / Tor'], ['authentication', 'Authentication Anomalies']],
    classify: row => {
      const text = eventText(row);
      if (/impossible.travel/.test(text)) return 'impossible';
      if (field(row, 'geoVpn', 'vpnDetected') === true || field(row, 'geoProxy', 'proxyDetected') === true
        || field(row, 'geoTor', 'torDetected') === true || field(row, 'geoHosting', 'datacenterIP') === true) return 'privacy';
      if (/failed.login|authentication|login/.test(text)) return 'authentication';
      if (/gps.location|gps.status|geo.fence|unusual.login.location|new.device.location|multiple.geologins/.test(text)
        || field(row, 'highRiskCountry') === true) return 'location';
      return 'other';
    },
    metrics: rows => [
      ['Total Geo Events', rows.length, COLORS.blue],
      ['Critical Alerts', count(rows, row => severity(row) === 'critical'), COLORS.red],
      ['GPS Positions', count(rows, row => field(row, 'gpsStatus', 'gps_status') === 'available' && field(row, 'gpsLat', 'gps_lat') !== '—'), COLORS.green],
      ['Radius Violations', count(rows, row => /geo.fence.radius.violation/.test(eventText(row))), COLORS.red],
      ['Impossible Travel', count(rows, row => /impossible.travel/.test(eventText(row))), COLORS.orange],
      ['VPN / Proxy / Tor', count(rows, row => field(row, 'geoVpn', 'vpnDetected') === true || field(row, 'geoProxy', 'proxyDetected') === true || field(row, 'geoTor', 'torDetected') === true || field(row, 'geoHosting') === true), COLORS.purple],
      ['Affected Users', unique(rows, row => field(row, 'username', 'user', 'userName')), COLORS.yellow],
      ['Affected Endpoints', unique(rows, host), COLORS.cyan],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host], ['User', row => field(row, 'username', 'user', 'userName')],
      ['Detection', row => field(row, 'detectionRuleId', 'ruleId')], ['Source IP', row => field(row, 'srcip', 'sourceIp', 'src_ip')],
      ['Country', row => field(row, 'geoCountry', 'country')], ['City', row => field(row, 'geoCity', 'city')],
      ['GPS Latitude', row => field(row, 'gpsLat', 'gps_lat')], ['GPS Longitude', row => field(row, 'gpsLon', 'gps_lon')],
      ['GPS Accuracy (m)', row => field(row, 'gpsAccuracyMeters', 'gps_accuracy_meters')], ['GPS Provider', row => field(row, 'gpsProvider', 'gps_provider')],
      ['GPS Status', row => field(row, 'gpsStatus', 'gps_status')], ['Distance (m)', row => field(row, 'geoFenceDistanceMeters')],
      ['Risk Score', row => field(row, 'riskScore', 'risk_score')], ['Status', status],
    ],
  },
  24: {
    title: 'Service Monitoring',
    subtitle: 'Windows services, Linux systemd daemons, lifecycle changes, health and anti-tamper detections',
    categories: [['all', 'All Service Events'], ['lifecycle', 'Start / Stop / Restart'], ['created', 'New Services'], ['failure', 'Failures / Deletions'], ['configuration', 'Configuration Changes'], ['security', 'Security Service Alerts']],
    classify: row => {
      const text = eventText(row);
      if (field(row, 'serviceSecurityCritical', 'security_service') === true && /stopped|failed|deleted|config|disabled/.test(text)) return 'security';
      if (/service.created|proc.asset.created/.test(text)) return 'created';
      if (/service.failed|service.deleted|proc.asset.removed/.test(text)) return 'failure';
      if (/service.config.changed|proc.asset.changed|binary|account|startup.type/.test(text)) return 'configuration';
      if (/service.started|service.stopped|service.restarted|service.control/.test(text)) return 'lifecycle';
      return 'other';
    },
    metrics: rows => [
      ['Total Service Events', rows.length, COLORS.blue],
      ['Critical Alerts', count(rows, row => severity(row) === 'critical'), COLORS.red],
      ['New Services', count(rows, row => /service.created|proc.asset.created/.test(eventText(row))), COLORS.purple],
      ['Service Failures', count(rows, row => /service.failed/.test(eventText(row))), COLORS.red],
      ['Configuration Changes', count(rows, row => /service.config.changed|proc.asset.changed/.test(eventText(row))), COLORS.orange],
      ['Security Service Events', count(rows, row => field(row, 'serviceSecurityCritical', 'security_service') === true), COLORS.yellow],
      ['Affected Services', unique(rows, row => field(row, 'serviceName', 'service_name', 'inventoryName')), COLORS.cyan],
      ['Affected Endpoints', unique(rows, host), COLORS.green],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host], ['OS', row => field(row, 'osType', 'os', 'platform')],
      ['Service', row => field(row, 'serviceName', 'service_name', 'inventoryName')], ['Event', row => field(row, 'serviceEventType', 'service_event_type', 'ruleId')],
      ['Previous State', row => field(row, 'servicePreviousStatus', 'previous_status')], ['Current State', row => field(row, 'serviceCurrentStatus', 'current_status')],
      ['Account', row => field(row, 'serviceAccount', 'service_account')], ['Binary', row => field(row, 'serviceBinaryPath', 'service_binary_path')],
      ['SHA-256', row => field(row, 'serviceBinarySha256', 'service_binary_sha256')], ['Signature', row => field(row, 'serviceSignatureStatus', 'service_signature_status')],
      ['Risk Score', row => field(row, 'riskScore', 'risk_score')], ['MITRE', row => field(row, 'mitreId', 'mitre_id', 'mitreTechnique')], ['Status', status],
    ],
  },
  25: {
    title: 'Hash / Signature Analysis Monitoring',
    subtitle: 'File hashes, baseline changes, digital-signature trust and threat-intelligence correlation',
    categories: [['all', 'All Hash Events'], ['malicious', 'Malicious / IOC Matches'], ['mismatch', 'Hash Mismatches'], ['unsigned', 'Unsigned Files'], ['certificate', 'Certificate Failures'], ['trusted', 'Trusted Signatures']],
    classify: row => {
      const signature = String(field(row, 'signatureStatus', 'signature_status', 'processSignatureStatus')).toUpperCase();
      const text = eventText(row);
      if (field(row, 'threatIntelMatch', 'iocMatched') === true || /known.malicious|malware.hash|ransomware.hash|apt.hash|trojan.hash|threat.intel|malicious/i.test(`${field(row, 'reputation', 'vtVerdict')} ${text}`)) return 'malicious';
      if (field(row, 'hashMismatch', 'hash_mismatch') === true || /hash.mismatch|hash.changed|critical.file.hash.changed|signed.file.hash.changed/.test(text)) return 'mismatch';
      if (signature === 'UNSIGNED' || /unsigned.executable/.test(text)) return 'unsigned';
      if (['INVALID', 'EXPIRED', 'REVOKED', 'UNKNOWN', 'UNTRUSTED_PUBLISHER', 'CERTIFICATE_CHAIN_FAILURE'].includes(signature)) return 'certificate';
      if (signature === 'VALID' || field(row, 'allowlisted') === true || /known.good|trusted/.test(`${field(row, 'reputation')} ${text}`)) return 'trusted';
      return 'other';
    },
    metrics: rows => [
      ['Total Hash Events', rows.length, COLORS.blue],
      ['Malicious Hashes', count(rows, row => field(row, 'threatIntelMatch', 'iocMatched') === true || /malicious/i.test(String(field(row, 'reputation', 'vtVerdict')))), COLORS.red],
      ['Hash Mismatches', count(rows, row => field(row, 'hashMismatch', 'hash_mismatch') === true || /hash.mismatch|hash.changed/.test(eventText(row))), COLORS.orange],
      ['Unsigned Files', count(rows, row => String(field(row, 'signatureStatus', 'signature_status', 'processSignatureStatus')).toUpperCase() === 'UNSIGNED'), COLORS.yellow],
      ['Signature Failures', count(rows, row => ['INVALID', 'EXPIRED', 'REVOKED', 'UNTRUSTED_PUBLISHER', 'CERTIFICATE_CHAIN_FAILURE'].includes(String(field(row, 'signatureStatus', 'signature_status', 'processSignatureStatus')).toUpperCase())), COLORS.purple],
      ['Valid Signatures', count(rows, row => String(field(row, 'signatureStatus', 'signature_status', 'processSignatureStatus')).toUpperCase() === 'VALID'), COLORS.green],
      ['Affected Endpoints', unique(rows, host), COLORS.cyan],
      ['IOC Matches', count(rows, row => field(row, 'threatIntelMatch', 'iocMatched') === true), COLORS.red],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host],
      ['File', row => field(row, 'fileName', 'file_name')], ['Path', row => field(row, 'filePath', 'file_path', 'processExe', 'process_exe')],
      ['SHA-256', row => field(row, 'sha256', 'fileHash', 'currentHash', 'processExecutableSha256', 'file_hash')],
      ['SHA-1', row => field(row, 'sha1', 'fileHashSha1', 'file_hash_sha1')], ['MD5', row => field(row, 'md5', 'fileHashMd5', 'processExecutableMd5', 'file_hash_md5')],
      ['Signature', row => field(row, 'signatureStatus', 'signature_status', 'processSignatureStatus')], ['Publisher', row => field(row, 'publisher', 'processPublisher', 'signer')],
      ['Process', row => field(row, 'processName', 'process_name')], ['PID', row => field(row, 'pid')],
      ['Command Line', row => field(row, 'processCmdline', 'process_cmdline', 'commandLine', 'command_line', 'cmdline')],
      ['Threat Intel', row => field(row, 'threatIntelSource', 'reputation', 'vtVerdict')],
      ['Risk Score', row => field(row, 'hashSignatureRiskScore', 'riskScore', 'risk_score')], ['Status', status],
    ],
  },
  26: {
    title: 'Beaconing & C2 Traffic Detection',
    subtitle: 'Periodic callbacks, jitter, DNS/HTTP channels, process correlation and destination intelligence',
    categories: [['all', 'All Beaconing Events'], ['dns', 'DNS Beaconing'], ['http', 'HTTP / HTTPS Beaconing'], ['low_slow', 'Low & Slow'], ['process', 'Process Correlation'], ['intel', 'Threat Intelligence Matches']],
    classify: row => {
      const text = eventText(row);
      const protocol = String(field(row, 'protocol')).toLowerCase();
      if (field(row, 'iocMatched') === true || /known c2|malicious destination|threat.intel|ioc/.test(text)) return 'intel';
      if (Number(field(row, 'averageInterval', 'average_interval')) >= 600 || /low.{0,3}slow/.test(text)) return 'low_slow';
      if (/^dns$/.test(protocol) || /dns beacon/.test(text)) return 'dns';
      if (/^(http|https|tls)$/.test(protocol)) return 'http';
      if (field(row, 'processName', 'process_name') !== '—') return 'process';
      return 'other';
    },
    metrics: rows => [
      ['Total Beacon Events', rows.length, COLORS.blue],
      ['Critical Alerts', count(rows, row => severity(row) === 'critical'), COLORS.red],
      ['Affected Endpoints', unique(rows, host), COLORS.orange],
      ['C2 Destinations', unique(rows, row => field(row, 'destip', 'dst_ip', 'domain')), COLORS.yellow],
      ['DNS Beacons', count(rows, row => /^dns$/i.test(String(field(row, 'protocol'))) || /dns beacon/.test(eventText(row))), COLORS.purple],
      ['Low & Slow', count(rows, row => Number(field(row, 'averageInterval', 'average_interval')) >= 600), COLORS.cyan],
      ['Processes', unique(rows, row => field(row, 'processName', 'process_name')), COLORS.green],
      ['IOC Matches', count(rows, row => field(row, 'iocMatched') === true || /known c2|malicious destination|threat.intel|ioc/.test(eventText(row))), COLORS.red],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host], ['User', row => field(row, 'username', 'user')],
      ['Process', row => field(row, 'processName', 'process_name')], ['PID', row => field(row, 'pid')],
      ['Command Line', row => field(row, 'processCmdline', 'process_cmdline', 'commandLine', 'command_line', 'cmdline')],
      ['Destination', row => field(row, 'destip', 'dst_ip', 'domain')], ['Port', row => field(row, 'destPort', 'dst_port')],
      ['Protocol', row => field(row, 'protocol')], ['Connections', row => field(row, 'connectionCount', 'connection_count')],
      ['Avg Interval', row => field(row, 'averageInterval', 'average_interval')], ['Jitter', row => field(row, 'jitterSeconds', 'jitter_seconds')],
      ['Threat Score', row => field(row, 'riskScore', 'risk_score')], ['MITRE', row => field(row, 'mitreId', 'mitre_id', 'mitreTechnique')], ['Status', status],
    ],
  },
  27: {
    title: 'Encryption & Ransomware Detection',
    subtitle: 'Mass encryption, ransom notes, recovery tampering and correlated malware activity',
    categories: [['all', 'All Ransomware Events'], ['impact', 'Encryption / Destruction'], ['notes', 'Ransom Notes / Extensions'], ['recovery', 'Shadow Copy / Backup Tamper'], ['process', 'Encryption Processes'], ['correlated', 'IOC / Malware Correlation']],
    classify: row => {
      const text = eventText(row);
      if (/ransomware.note|ransom note|decrypt.instructions|recover.files|ransomware.extension|\.locked|\.encrypted|\.crypt/.test(text)) return 'notes';
      if (/shadow|vss|backup|recovery|t1490/.test(text)) return 'recovery';
      if (/encryption.proc|openssl|gpg|cipher|7z|winrar/.test(text)) return 'process';
      if (/yara|ioc|hash|malware.quarantined|threat.intel/.test(text)) return 'correlated';
      if (/mass.encrypt|high.entropy|mass.delet|data destruction|t1485|t1486/.test(text)) return 'impact';
      return 'other';
    },
    metrics: rows => [
      ['Total Ransomware Events', rows.length, COLORS.red],
      ['Critical Alerts', count(rows, row => severity(row) === 'critical'), COLORS.red],
      ['Mass Encryption', count(rows, row => /mass.encrypt|high.entropy|t1486/.test(eventText(row))), COLORS.orange],
      ['Ransom Notes / Extensions', count(rows, row => /ransomware.note|ransom note|ransomware.extension|\.locked|\.encrypted|\.crypt/.test(eventText(row))), COLORS.yellow],
      ['Recovery Tampering', count(rows, row => /shadow|vss|backup|recovery|t1490/.test(eventText(row))), COLORS.purple],
      ['Affected Files', rows.reduce((sum, row) => sum + ransomwareAffectedFiles(row), 0), COLORS.orange],
      ['Processes', unique(rows, row => field(row, 'processName', 'process_name')), COLORS.cyan],
      ['Endpoints', unique(rows, host), COLORS.green],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host], ['Detection', row => field(row, 'detectionRuleId', 'ruleId')],
      ['Suspicious Process', ransomwareProcessName], ['PID', ransomwarePid],
      ['Command Line', ransomwareCommandLine],
      ['File / Directory', ransomwareFileLocation],
      ['Affected Files', ransomwareAffectedFiles], ['Entropy', ransomwareEntropy],
      ['Variant / Family', row => field(row, 'threatFamily', 'threat_family', 'malwareFamily', 'malware_family', 'malwareType', 'malware_type')],
      ['Canary Status', ransomwareCanaryStatus],
      ['Risk Score', row => field(row, 'riskScore', 'risk_score')], ['MITRE', row => field(row, 'mitreId', 'mitre_id', 'mitreTechnique')], ['Status', status],
    ],
  },
  28: {
    title: 'Living-off-the-Land (LOLBins) Detection',
    subtitle: 'Native-tool abuse, encoded execution, download cradles and suspicious parent-child activity',
    categories: [['all', 'All LOLBin Events'], ['encoded', 'Encoded Commands'], ['download', 'Download Cradles'], ['office', 'Office Parent Spawns'], ['proxy', 'Proxy Execution'], ['persistence', 'Persistence'], ['lateral', 'Lateral Movement']],
    classify: row => {
      const text = eventText(row);
      if (/winword|excel|outlook|powerpnt|office/.test(`${field(row, 'parentProcessName')} ${text}`.toLowerCase())) return 'office';
      if (/encodedcommand|frombase64string|base64|\s-enc(?:\s|$)|invoke-expression|\biex\b/.test(text)) return 'encoded';
      if (/invoke-webrequest|webclient|downloadfile|downloadstring|start-bitstransfer|urlcache|bitsadmin|\bcurl\b|\bwget\b/.test(text)) return 'download';
      if (/scheduled.task|schtasks|runonce|run.key|startup|systemd|cron|service.create|wmi.persistence/.test(text)) return 'persistence';
      if (/psexec|winrm|remote.service|remote.scheduled|admin.share|remote.powershell|\bssh\b|rdp/.test(text)) return 'lateral';
      if (/rundll32|regsvr32|mshta|installutil|msbuild|odbcconf|presentationhost|control\.exe|mmc\.exe/.test(text)) return 'proxy';
      return 'other';
    },
    metrics: rows => [
      ['Total LOLBin Events', rows.length, COLORS.blue],
      ['Critical Alerts', count(rows, row => severity(row) === 'critical'), COLORS.red],
      ['Encoded Commands', count(rows, row => /encodedcommand|frombase64string|base64|\s-enc(?:\s|$)|invoke-expression|\biex\b/.test(eventText(row))), COLORS.orange],
      ['Download Cradles', count(rows, row => /invoke-webrequest|webclient|downloadfile|downloadstring|start-bitstransfer|urlcache|bitsadmin|\bcurl\b|\bwget\b/.test(eventText(row))), COLORS.red],
      ['Office Parent Spawns', count(rows, row => /winword|excel|outlook|powerpnt|office/.test(String(field(row, 'parentProcessName')).toLowerCase())), COLORS.purple],
      ['Persistence / Lateral', count(rows, row => /schtasks|runonce|startup|systemd|cron|psexec|winrm|remote.service|admin.share/.test(eventText(row))), COLORS.yellow],
      ['Abused Binaries', unique(rows, row => field(row, 'processName')), COLORS.cyan],
      ['Affected Endpoints', unique(rows, host), COLORS.green],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host], ['LOLBin Binary', row => field(row, 'processName')],
      ['PID', row => field(row, 'pid')], ['Parent Process', row => field(row, 'parentProcessName')], ['Username', row => field(row, 'username')],
      ['Command Line', row => field(row, 'processCmdline', 'commandLine', 'process_cmdline', 'command_line', 'cmdline')], ['Rule', row => field(row, 'detectionRuleId', 'ruleId')],
      ['Risk Score', row => field(row, 'riskScore')], ['MITRE', row => field(row, 'mitreId', 'mitreTechnique')], ['Status', status],
    ],
  },
  29: {
    title: 'Memory Overflow & Process Exploitation',
    subtitle: 'Memory pressure, corruption, injection and protected-process activity',
    categories: [['all', 'All Memory Events'], ['pressure', 'Pressure / OOM'], ['leak', 'Leaks / Allocation'], ['corruption', 'Stack / Heap Corruption'], ['injection', 'Injection / Executable Memory'], ['protected', 'Protected Process Access'], ['malware', 'Fileless / In-memory Malware']],
    classify: row => {
      const text = eventText(row);
      if (/pressure|exhaustion|oom|high.memory/.test(text)) return 'pressure';
      if (/leak|allocation/.test(text)) return 'leak';
      if (/stack|heap|out.of.bounds|segmentation|access.violation/.test(text)) return 'corruption';
      if (/inject|remote.thread|hollow|reflective|rwx|executable.region/.test(text)) return 'injection';
      if (/lsass|credential|agent.tamper|sensitive.process/.test(text)) return 'protected';
      if (/fileless|ransomware|shellcode|obfuscat/.test(text)) return 'malware';
      return 'other';
    },
    metrics: rows => [
      ['Total Memory Events', rows.length, COLORS.blue],
      ['Critical Alerts', count(rows, row => severity(row) === 'critical'), COLORS.red],
      ['Overflow / Corruption', count(rows, row => /buffer|stack|heap|out.of.bounds|segmentation|access.violation/.test(eventText(row))), COLORS.orange],
      ['Process Injection', count(rows, row => /inject|remote.thread|hollow|reflective/.test(eventText(row))), COLORS.purple],
      ['Memory Leaks / OOM', count(rows, row => /leak|exhaustion|oom/.test(eventText(row))), COLORS.yellow],
      ['Protected Access', count(rows, row => /lsass|credential|agent.tamper|sensitive.process/.test(eventText(row))), COLORS.red],
      ['Processes', unique(rows, row => field(row, 'processName')), COLORS.cyan],
      ['Endpoints', unique(rows, host), COLORS.green],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Hostname', host], ['Process', row => field(row, 'processName')],
      ['PID', row => field(row, 'pid')], ['Event Type', row => field(row, 'eventType')], ['Rule', row => field(row, 'detectionRuleId', 'ruleId')],
      ['Risk Score', row => field(row, 'riskScore')], ['Status', status],
    ],
  },
  30: {
    title: 'DNS Cache Poisoning',
    subtitle: 'Poisoning, resolver, hosts-file and TTL anomaly activity',
    categories: [['all', 'All DNS Cache Events'], ['poisoning', 'Poisoning / Spoofing'], ['resolver', 'Resolver Changes'], ['hosts', 'Hosts File Changes'], ['ttl', 'TTL Anomalies'], ['private', 'Unexpected Private Answers']],
    classify: row => {
      const text = eventText(row);
      if (/resolver/.test(text)) return 'resolver';
      if (/hosts/.test(text)) return 'hosts';
      if (/ttl/.test(text)) return 'ttl';
      if (/private/.test(text)) return 'private';
      if (/poison|spoof|fake/.test(text)) return 'poisoning';
      return 'other';
    },
    metrics: rows => [
      ['Total DNS Events', rows.length, COLORS.blue],
      ['Critical Alerts', count(rows, row => severity(row) === 'critical'), COLORS.red],
      ['Poisoning Alerts', count(rows, row => /poison|spoof|fake/.test(eventText(row))), COLORS.red],
      ['Resolver Changes', count(rows, row => /resolver/.test(eventText(row))), COLORS.orange],
      ['Hosts File Changes', count(rows, row => /hosts/.test(eventText(row))), COLORS.yellow],
      ['TTL Anomalies', count(rows, row => /ttl/.test(eventText(row))), COLORS.purple],
      ['Domains', unique(rows, row => field(row, 'domain')), COLORS.cyan],
      ['Endpoints', unique(rows, host), COLORS.green],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Domain', row => field(row, 'domain')], ['Query Type', row => field(row, 'queryType')],
      ['Source IP', row => field(row, 'srcip', 'sourceIp')], ['Observed IP', row => field(row, 'poisonedIp', 'destip')],
      ['Resolver', row => field(row, 'resolverIp', 'dnsServer')], ['Rule', row => field(row, 'detectionRuleId', 'ruleId')], ['Status', status],
    ],
  },
  31: {
    title: 'DNS Sinkhole',
    subtitle: 'Sinkhole hits, blocked responses and malicious-domain activity',
    categories: [['all', 'All Sinkhole Events'], ['sinkhole', 'Sinkhole Hits'], ['blocked', 'Blocked Responses'], ['botnet', 'Botnet / C2'], ['phishing', 'Phishing'], ['dga', 'DGA Domains']],
    classify: row => {
      const text = eventText(row);
      if (/botnet|c2|c&c/.test(text)) return 'botnet';
      if (/phish/.test(text)) return 'phishing';
      if (/dga/.test(text)) return 'dga';
      if (row.blocked || /block|refused|nxdomain|deny/.test(text)) return 'blocked';
      if (/sinkhole/.test(text)) return 'sinkhole';
      return 'other';
    },
    metrics: rows => [
      ['Total DNS Events', rows.length, COLORS.blue],
      ['Critical Alerts', count(rows, row => severity(row) === 'critical'), COLORS.red],
      ['Sinkhole Hits', count(rows, row => /sinkhole/.test(eventText(row))), COLORS.red],
      ['Blocked Responses', count(rows, row => row.blocked || /block|refused|nxdomain|deny/.test(eventText(row))), COLORS.orange],
      ['Botnet / C2', count(rows, row => /botnet|c2|c&c/.test(eventText(row))), COLORS.red],
      ['Phishing / DGA', count(rows, row => /phish|dga/.test(eventText(row))), COLORS.purple],
      ['Domains', unique(rows, row => field(row, 'domain')), COLORS.yellow],
      ['Endpoints', unique(rows, host), COLORS.cyan],
    ],
    columns: [
      ['Timestamp', eventTime], ['Severity', severity], ['Domain', row => field(row, 'domain')], ['Query Type', row => field(row, 'queryType')],
      ['Source IP', row => field(row, 'srcip', 'sourceIp')], ['Response', row => field(row, 'responseType', 'responseCode')],
      ['Threat Category', row => field(row, 'threatCategory')], ['Rule', row => field(row, 'detectionRuleId', 'ruleId')], ['Status', status],
    ],
  },
};

function raw(row) {
  const direct = row?.rawEvent && typeof row.rawEvent === 'object' ? row.rawEvent : {};
  const nested = direct.raw && typeof direct.raw === 'object' ? direct.raw : {};
  return { ...direct, ...nested };
}
function field(row, ...keys) {
  for (const key of keys) {
    const value = row?.[key] ?? raw(row)?.[key];
    if (value !== undefined && value !== null && value !== '') return value;
  }
  return '—';
}
function eventTime(row) { return row?.createdAt || row?.timestamp || '—'; }
function host(row) { return row?.hostname || row?.agentName || row?.systemId?.hostname || row?.systemId?.name || '—'; }
function authReportOs(row) { return field(row, 'osType', 'os', 'platform') !== '—' ? field(row, 'osType', 'os', 'platform') : (row?.systemId?.osType || row?.systemId?.os || '—'); }
function authReportSourceIp(row) {
  const reported = field(row, 'srcip', 'src_ip', 'sourceIp', 'source_ip', 'ipAddress', 'ip', 'remoteIp', 'remote_ip', 'clientIp', 'client_ip');
  return reported !== '—' ? reported : (row?.systemId?.ip || row?.systemId?.ipAddress || '—');
}
function uebaReportSourceIp(row) {
  const reported = field(row, 'srcip', 'srcIp', 'src_ip', 'sourceIp', 'source_ip', 'clientIp', 'client_ip', 'remoteIp', 'remote_ip', 'ipAddress', 'ip');
  if (reported !== '—') return reported;
  const connection = field(row, 'networkConnections', 'network_connections');
  const first = Array.isArray(connection) ? connection[0] : null;
  return first?.srcip || first?.srcIp || first?.sourceIp || first?.localAddress || row?.systemId?.ip || row?.systemId?.ipAddress || '—';
}
function uebaReportProcess(row) {
  return field(row, 'processName', 'process_name', 'sourceProcessName', 'source_process_name', 'targetProcessName', 'target_process_name', 'parentProcessName', 'parent_process_name', 'processExe', 'process_exe', 'image', 'executable');
}
function uebaReportCommandLine(row) {
  return field(row, 'processCmdline', 'process_cmdline', 'commandLine', 'command_line', 'cmdline', 'command', 'processCommandLine', 'process_command_line');
}
function uebaReportMitre(row) {
  const value = field(row, 'mitreId', 'mitre_id', 'mitreTechnique', 'mitre_technique', 'mitreTechniques', 'mitre_techniques', 'technique');
  if (Array.isArray(value)) return value.filter(Boolean).join(', ') || '—';
  if (value !== '—') return value;
  const factors = field(row, 'uebaRiskFactors', 'ueba_risk_factors');
  const matches = (Array.isArray(factors) ? factors : [factors]).flatMap(item => String(item || '').match(/T\d{4}(?:\.\d{3})?/gi) || []);
  return [...new Set(matches)].join(', ') || '—';
}
function severity(row) { return String(row?.severity || 'unknown').toLowerCase(); }
function status(row) { return row?.status || (row?.blocked ? 'blocked' : 'open'); }
function eventText(row) { return `${field(row, 'eventType')} ${field(row, 'ruleId')} ${field(row, 'detectionRuleId')} ${field(row, 'description')} ${field(row, 'threatCategory')} ${field(row, 'responseType')} ${field(row, 'scriptName', 'script_name')} ${field(row, 'scriptPath', 'script_path')} ${field(row, 'interpreter')} ${field(row, 'processName', 'process_name')} ${field(row, 'processCmdline', 'commandLine', 'process_cmdline', 'command_line', 'cmdline')} ${field(row, 'detectionReasons', 'detection_reasons')} ${field(row, 'matchedPatterns', 'matched_patterns')}`.toLowerCase(); }
function persistenceInventoryItem(row) {
  const item = row?.inventoryItem ?? row?.inventory_item ?? raw(row)?.inventoryItem ?? raw(row)?.inventory_item;
  return item && typeof item === 'object' ? item : {};
}
function persistenceLocation(row) {
  const direct = field(row, 'persistenceLocation', 'persistence_location', 'keyPath', 'sourcePath', 'location', 'path', 'target');
  if (direct !== '—') return direct;
  const item = persistenceInventoryItem(row);
  return item.location || item.path || item.unit_file || item.file_path || '—';
}
function persistenceEntryName(row) {
  const direct = field(row, 'persistenceKey', 'persistence_key', 'inventoryName', 'inventory_name', 'taskName', 'serviceName');
  if (direct !== '—') return direct;
  const item = persistenceInventoryItem(row);
  return item.name || item.task_name || item.service_name || item.key || item.fingerprint || '—';
}
function persistenceCommand(row) {
  const direct = field(row, 'persistenceAction', 'persistence_action', 'serviceBinaryPath', 'processCmdline', 'commandLine', 'process_cmdline', 'command_line', 'command', 'executable');
  if (direct !== '—') return direct;
  const item = persistenceInventoryItem(row);
  return item.command || item.exec_start || item.binary_path || item.action || '—';
}
function dataSensitiveFileName(row) {
  const direct = field(row, 'fileName', 'file_name', 'filename', 'file');
  if (direct !== '—') return direct;
  const path = field(row, 'filePath', 'file_path', 'path');
  return path === '—' ? 'Not reported' : String(path).split(/[/\\]/).filter(Boolean).pop() || path;
}
function dataDestinationChannel(row) {
  const values = [
    field(row, 'destinationDomain', 'destination_domain', 'domain', 'destip', 'destinationIp', 'dst_ip'),
    field(row, 'transferChannel', 'transfer_channel', 'channel', 'device', 'mountPath', 'mount_path'),
  ].filter(value => value !== '—');
  return [...new Set(values.map(String))].join(' / ') || 'Local endpoint';
}
function dataClassificationDisplay(row) {
  const reported = field(row, 'dataClassification', 'data_classification', 'classification');
  if (reported !== '—' && String(reported).toLowerCase() !== 'unknown') return reported;
  const sensitivity = String(field(row, 'sensitivityType', 'sensitivity_type')).toLowerCase();
  const path = String(field(row, 'filePath', 'file_path', 'path')).toLowerCase();
  const evidence = `${sensitivity} ${path}`;
  if (/credential|secret|private.?key|ssh.?key|password/.test(evidence)) return 'Secret';
  if (/source.?code|database|backup|certificate|config/.test(evidence)) return 'Restricted';
  if (/finance|payroll|human.resources|\bhr\b|confidential|sensitive/.test(evidence)) return 'Confidential';
  return path !== '—' ? 'Internal' : 'Unknown';
}
function dataActionExecuted(row) {
  const response = field(row, 'actionTaken');
  if (response !== '—' && String(response).toLowerCase() !== 'none') return response;
  const containment = field(row, 'containmentStatus');
  if (containment !== '—' && String(containment).toLowerCase() !== 'none') return containment;
  const lifecycle = field(row, 'fileAction', 'file_action', 'dataEventType', 'data_event_type', 'eventType', 'ruleId');
  if (lifecycle !== '—') return lifecycle;
  const generic = field(row, 'action');
  return generic === '—' ? 'Observed' : generic;
}
function emailAuthentication(row) {
  const auth = row?.emailAuth || raw(row)?.email_auth || {};
  const values = ['spf', 'dkim', 'dmarc'].map(method => auth?.[method] ? `${method.toUpperCase()}: ${auth[method]}` : '').filter(Boolean);
  return values.length ? values.join(' | ') : '—';
}
function emailMitre(row) {
  const direct = [
    row?.mitreId, row?.mitre_id, row?.mitreTechnique, row?.technique,
    raw(row)?.mitreId, raw(row)?.mitre_id, raw(row)?.mitreTechnique,
    ...(Array.isArray(row?.mitreTechniques) ? row.mitreTechniques : []),
  ].filter(Boolean).flatMap(value => Array.isArray(value) ? value : [value]).map(value => String(value).trim()).filter(Boolean);
  if (direct.length) return [...new Set(direct)].join(' · ');
  const rule = String(field(row, 'ruleId', 'eventType')).toUpperCase();
  if (/WEBMAIL_LINK_OPEN/.test(rule) && row?.actionable) return 'T1204.001 · Malicious Link';
  if (/ATTACHMENT_(?:EXECUTED|MALWARE)|SUSPICIOUS_CHILD_PROCESS/.test(rule)) return 'T1204.002 · Malicious File';
  if (/ATTACHMENT_DOWNLOADED/.test(rule) && row?.actionable) return 'T1566.001 · Spearphishing Attachment';
  return 'Not mapped';
}
function emailText(row) {
  return `${eventText(row)} ${field(row, 'emailSender', 'sender')} ${field(row, 'emailRecipient', 'recipient')} ${field(row, 'emailSubject', 'subject')} ${field(row, 'url', 'domain')} ${field(row, 'fileName', 'filename')} ${emailAuthentication(row)}`.toLowerCase();
}
function inventoryItems(row) {
  const value = row?.inventoryItems ?? row?.inventory_items ?? raw(row)?.inventoryItems ?? raw(row)?.inventory_items;
  return Array.isArray(value) ? value : [];
}
function inventoryRowCount(row) {
  const items = inventoryItems(row);
  if (items.length) return items.length;
  const reported = Number(field(row, 'inventoryCount', 'inventory_count'));
  return Number.isFinite(reported) ? reported : 0;
}
function inventoryItemCount(rows, type) {
  return rows.filter(row => String(field(row, 'inventoryType', 'inventory_type')).toLowerCase() === type)
    .reduce((sum, row) => sum + inventoryRowCount(row), 0);
}
function inventoryItemNames(row) {
  const names = inventoryItems(row).map(item => item?.kb || item?.id || item?.name).filter(Boolean);
  return names.length ? names.join(', ') : field(row, 'inventoryName', 'inventory_name', 'kb', 'package');
}
function ransomwareRawText(row) { return `${row?.full_log || ''} ${field(row, 'raw_log')} ${row?.description || ''}`; }
function ransomwareProcessName(row) {
  const direct = field(row, 'processName', 'process_name');
  return direct !== '—' ? direct : ransomwareRawText(row).match(/(?:^|\|)proc=([^|]+)/i)?.[1]?.trim() || 'Not captured';
}
function ransomwarePid(row) {
  const direct = field(row, 'pid', 'processId', 'process_id');
  return direct !== '—' ? direct : ransomwareRawText(row).match(/(?:^|\|)pid=(\d+)/i)?.[1] || 'Not captured';
}
function ransomwareCommandLine(row) {
  const direct = field(row, 'processCmdline', 'commandLine', 'process_cmdline', 'command_line', 'cmdline');
  return direct !== '—' ? direct : ransomwareRawText(row).match(/(?:^|\|)cmd=(.+)$/i)?.[1]?.trim() || 'Not captured for filesystem-only event';
}
function ransomwareFileLocation(row) {
  const direct = field(row, 'filePath', 'file_path', 'affectedDirectory', 'affected_directory');
  return direct !== '—' ? direct : ransomwareRawText(row).match(/(?:^|\|)path=([^|]+)/i)?.[1]?.trim() || 'Not captured';
}
function ransomwareCanaryStatus(row) {
  const direct = field(row, 'canary', 'honeytoken', 'canaryStatus', 'canary_status');
  return direct !== '—' ? direct : ransomwareRawText(row).match(/(?:^|\|)(?:canary|honeytoken)=([^|]+)/i)?.[1]?.trim() || 'No telemetry';
}
function ransomwareAffectedFiles(row) {
  const direct = Number(field(row, 'affectedFiles', 'affected_files'));
  if (Number.isFinite(direct) && direct > 0) return direct;
  const text = ransomwareRawText(row);
  const modified = Number(text.match(/modified=(\d+)/i)?.[1] || 0);
  const renamed = Number(text.match(/renamed=(\d+)/i)?.[1] || 0);
  const deleted = Number(text.match(/deleted=(\d+)/i)?.[1] || 0);
  return modified + renamed || deleted || Number(text.match(/(?:count|files?)=(\d+)/i)?.[1] || 0);
}
function ransomwareEntropy(row) {
  const direct = Number(field(row, 'entropy'));
  if (Number.isFinite(direct)) return direct;
  const parsed = Number(ransomwareRawText(row).match(/(?:avg_entropy|entropy)=([0-9.]+)/i)?.[1]);
  return Number.isFinite(parsed) ? parsed : '—';
}
function count(rows, predicate) { return rows.filter(predicate).length; }
function unique(rows, picker) { return new Set(rows.map(picker).filter(value => value && value !== '—')).size; }
function escapeHtml(value) { return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char])); }
function csvCell(value) {
  let text = String(value ?? '');
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}
function download(content, filename, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const anchor = document.createElement('a');
  anchor.href = url; anchor.download = filename; document.body.appendChild(anchor); anchor.click(); anchor.remove();
  URL.revokeObjectURL(url);
}

export default function CapabilityReportsPanel({ capabilityId, alerts = [] }) {
  const definition = DEFINITIONS[capabilityId];
  const { company, user } = useAuth();
  const companyId = company?._id || user?.companyId?._id || user?.companyId;
  const [period, setPeriod] = useState('daily');
  const [category, setCategory] = useState('all');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);
  const [error, setError] = useState('');
  const [liveConnected, setLiveConnected] = useState(false);
  const [lastRefreshedAt, setLastRefreshedAt] = useState(null);
  const latestAlertsRef = useRef(alerts);
  const refreshTimerRef = useRef(null);
  const requestSequenceRef = useRef(0);

  useEffect(() => { latestAlertsRef.current = alerts; }, [alerts]);

  const localReport = useCallback((selectedPeriod, selectedCategory) => {
    const periodDef = PERIODS.find(item => item.key === selectedPeriod) || PERIODS[0];
    const until = new Date();
    const since = new Date(until.getTime() - periodDef.days * 86400000);
    const rows = latestAlertsRef.current.filter(row => {
      const time = new Date(eventTime(row)).getTime();
      return Number.isFinite(time) && time >= since.getTime() && time <= until.getTime()
        && (selectedCategory === 'all' || definition.classify(row) === selectedCategory);
    });
    return { alerts: rows, total: rows.length, period: selectedPeriod, category: selectedCategory, since: since.toISOString(), until: until.toISOString(), source: 'dashboard-cache' };
  }, [definition]);

  const refreshReport = useCallback(async ({ quiet = false, allowFallback = false } = {}) => {
    const requestSequence = ++requestSequenceRef.current;
    if (!quiet) { setLoading(true); setError(''); setReport(null); }
    try {
      const endpoint = Number(capabilityId) === 20
        ? '/api-monitoring/report'
        : Number(capabilityId) === 19
          ? '/kernel-monitoring/report'
          : `/dashboard/capability-report/${capabilityId}`;
      const response = await api.get(endpoint, { params: { period, category }, skipCache: true });
      if (requestSequence !== requestSequenceRef.current) return;
      setReport({ ...response.data, source: 'backend' });
      setLastRefreshedAt(new Date());
      setError('');
    } catch (requestError) {
      if (requestSequence !== requestSequenceRef.current) return;
      if (allowFallback) {
        setReport(localReport(period, category));
        setLastRefreshedAt(new Date());
        setError(requestError.response?.data?.message || 'Backend report unavailable; current dashboard data is shown.');
      }
    } finally {
      if (!quiet && requestSequence === requestSequenceRef.current) setLoading(false);
    }
  }, [capabilityId, category, localReport, period]);

  const generate = () => refreshReport({ allowFallback: true });
  const hasReport = Boolean(report);

  useEffect(() => {
    if (!hasReport) return undefined;
    const socket = io(SOCKET_URL, socketOptions);
    const joinCompany = () => {
      setLiveConnected(true);
      if (companyId) socket.emit('join:company', companyId);
    };
    const handleDisconnect = () => setLiveConnected(false);
    const eventMatchesCapability = payload => {
      const event = payload?.alert || payload?.event || payload?.data || payload || {};
      const rawEvent = event?.rawEvent?.raw || event?.rawEvent || {};
      const ids = [
        event.capabilityId,
        ...(Array.isArray(event.capabilityIds) ? event.capabilityIds : []),
        rawEvent.capabilityId,
        rawEvent.capability_id,
        ...(Array.isArray(rawEvent.capabilityIds) ? rawEvent.capabilityIds : []),
        ...(Array.isArray(rawEvent.capability_ids) ? rawEvent.capability_ids : []),
      ];
      return ids.some(id => Number(id) === Number(capabilityId))
        || (Number(capabilityId) === 20 && Boolean(event.requestPath || event.url || event.provider || event.attackType));
    };
    const scheduleRefresh = payload => {
      if (!eventMatchesCapability(payload)) return;
      window.clearTimeout(refreshTimerRef.current);
      refreshTimerRef.current = window.setTimeout(() => refreshReport({ quiet: true }), 400);
    };
    const scheduleDeletedRefresh = () => {
      window.clearTimeout(refreshTimerRef.current);
      refreshTimerRef.current = window.setTimeout(() => refreshReport({ quiet: true }), 400);
    };
    const pollReport = () => {
      if (document.visibilityState !== 'hidden') refreshReport({ quiet: true });
    };

    socket.on('connect', joinCompany);
    socket.on('disconnect', handleDisconnect);
    socket.on('alert:new', scheduleRefresh);
    socket.on('alert:updated', scheduleRefresh);
    socket.on('alert:deleted', scheduleDeletedRefresh);
    if (Number(capabilityId) === 11) socket.on('ueba:event', scheduleRefresh);
    if (Number(capabilityId) === 7) {
      socket.on('system-change:event', scheduleRefresh);
      socket.on('system-change:updated', scheduleRefresh);
      socket.on('system-change:baseline-changed', scheduleDeletedRefresh);
    }
    if (Number(capabilityId) === 6) {
      socket.on('registry:event', scheduleRefresh);
      socket.on('registry:event-updated', scheduleRefresh);
      socket.on('registry:policy-updated', scheduleDeletedRefresh);
      socket.on('registry:baseline-updated', scheduleDeletedRefresh);
    }
    if (Number(capabilityId) === 8) socket.on('persistence:event', scheduleRefresh);
    if (Number(capabilityId) === 4) {
      socket.on('auth:event', scheduleRefresh);
      socket.on('authentication_event', scheduleRefresh);
      socket.on('authentication_alert', scheduleRefresh);
    }
    if (Number(capabilityId) === 5) {
      socket.on('memory:alert', scheduleRefresh);
      socket.on('memory:metric', scheduleRefresh);
    }
    if (Number(capabilityId) === 12) socket.on('data-security:event', scheduleRefresh);
    if (Number(capabilityId) === 10) socket.on('usb:event', scheduleRefresh);
    if (Number(capabilityId) === 13) socket.on('credential:event', scheduleRefresh);
    if (Number(capabilityId) === 14) socket.on('lateral:event', scheduleRefresh);
    if (Number(capabilityId) === 15) socket.on('email:event', scheduleRefresh);
    if (Number(capabilityId) === 18) socket.on('sandbox:event', scheduleRefresh);
    if (Number(capabilityId) === 17) socket.on('patch:event', scheduleRefresh);
    if (Number(capabilityId) === 20) {
      socket.on('api:event', scheduleRefresh);
      socket.on('waf:block', scheduleRefresh);
    }
    if (Number(capabilityId) === 19) socket.on('kernel:event', scheduleRefresh);
    if (Number(capabilityId) === 29) {
      socket.on('memory:alert', scheduleRefresh);
      socket.on('memory:alert-updated', scheduleRefresh);
    }
    if (Number(capabilityId) === 28) socket.on('lolbins:event', scheduleRefresh);
    if (Number(capabilityId) === 27) socket.on('ransomware:event', scheduleRefresh);
    if (Number(capabilityId) === 26) socket.on('beaconing:event', scheduleRefresh);
    if (Number(capabilityId) === 25) socket.on('hash:alert', scheduleRefresh);
    if (Number(capabilityId) === 24) socket.on('service:alert', scheduleRefresh);
    if (Number(capabilityId) === 21) socket.on('script:event', scheduleRefresh);
    if (Number(capabilityId) === 22) socket.on('time:anomaly', scheduleRefresh);
    if (Number(capabilityId) === 23) {
      socket.on('geo:event', scheduleRefresh);
      socket.on('geo:anomaly', scheduleRefresh);
    }
    if (socket.connected) joinCompany();
    const disconnectSocket = connectSocket(socket);
    const pollTimer = [12, 13, 14].includes(Number(capabilityId))
      ? window.setInterval(pollReport, 60000)
      : window.setInterval(pollReport, 30000);

    return () => {
      socket.off('connect', joinCompany);
      socket.off('disconnect', handleDisconnect);
      socket.off('alert:new', scheduleRefresh);
      socket.off('alert:updated', scheduleRefresh);
      socket.off('alert:deleted', scheduleDeletedRefresh);
      socket.off('ueba:event', scheduleRefresh);
      socket.off('system-change:event', scheduleRefresh);
      socket.off('system-change:updated', scheduleRefresh);
      socket.off('system-change:baseline-changed', scheduleDeletedRefresh);
      socket.off('registry:event', scheduleRefresh);
      socket.off('registry:event-updated', scheduleRefresh);
      socket.off('registry:policy-updated', scheduleDeletedRefresh);
      socket.off('registry:baseline-updated', scheduleDeletedRefresh);
      socket.off('persistence:event', scheduleRefresh);
      socket.off('auth:event', scheduleRefresh);
      socket.off('authentication_event', scheduleRefresh);
      socket.off('authentication_alert', scheduleRefresh);
      socket.off('memory:alert', scheduleRefresh);
      socket.off('memory:metric', scheduleRefresh);
      socket.off('data-security:event', scheduleRefresh);
      socket.off('usb:event', scheduleRefresh);
      socket.off('credential:event', scheduleRefresh);
      socket.off('lateral:event', scheduleRefresh);
      socket.off('email:event', scheduleRefresh);
      socket.off('sandbox:event', scheduleRefresh);
      socket.off('patch:event', scheduleRefresh);
      socket.off('api:event', scheduleRefresh);
      socket.off('waf:block', scheduleRefresh);
      socket.off('kernel:event', scheduleRefresh);
      socket.off('memory:alert', scheduleRefresh);
      socket.off('memory:alert-updated', scheduleRefresh);
      socket.off('lolbins:event', scheduleRefresh);
      socket.off('ransomware:event', scheduleRefresh);
      socket.off('beaconing:event', scheduleRefresh);
      socket.off('hash:alert', scheduleRefresh);
      socket.off('service:alert', scheduleRefresh);
      socket.off('script:event', scheduleRefresh);
      socket.off('time:anomaly', scheduleRefresh);
      socket.off('geo:event', scheduleRefresh);
      socket.off('geo:anomaly', scheduleRefresh);
      window.clearInterval(pollTimer);
      window.clearTimeout(refreshTimerRef.current);
      refreshTimerRef.current = null;
      disconnectSocket();
      setLiveConnected(false);
    };
  }, [capabilityId, companyId, hasReport, refreshReport]);

  const rows = report?.alerts || [];
  const metricCards = useMemo(() => definition.metrics(rows), [definition, rows]);
  const periodLabel = PERIODS.find(item => item.key === report?.period)?.label || '';
  const categoryLabel = definition.categories.find(item => item[0] === report?.category)?.[1] || 'All Events';
  const filenameBase = `${definition.title.toLowerCase().replace(/[^a-z0-9]+/g, '_')}_${report?.period || period}_${Date.now()}`;

  const exportCsv = () => {
    const content = [definition.columns.map(column => csvCell(column[0])).join(','), ...rows.map(row => definition.columns.map(column => csvCell(column[1](row))).join(','))].join('\n');
    download(content, `${filenameBase}.csv`, 'text/csv;charset=utf-8');
  };
  const exportJson = () => download(JSON.stringify({ ...report, title: `${definition.title} SOC Report`, exportedAt: new Date().toISOString() }, null, 2), `${filenameBase}.json`, 'application/json');
  const exportPdf = () => {
    const popup = window.open('', '_blank');
    if (!popup) { setError('Popups are blocked. Allow popups to print the report.'); return; }
    const cards = metricCards.map(([label, value, color]) => `<div class="card"><small style="color:${color}">${escapeHtml(label)}</small><strong style="color:${color}">${escapeHtml(value)}</strong></div>`).join('');
    const tableRows = rows.map(row => `<tr>${definition.columns.map(column => `<td>${escapeHtml(column[1](row))}</td>`).join('')}</tr>`).join('');
    popup.document.write(`<!doctype html><html><head><title>${escapeHtml(definition.title)} Report</title><style>body{font-family:Segoe UI,sans-serif;background:#060d16;color:#e2e8f0;padding:26px}.meta{color:#8ea0b8;margin:8px 0 20px}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.card{background:#0b1929;border:1px solid #1a3050;border-radius:8px;padding:12px}.card small,.card strong{display:block}.card strong{font-size:24px;margin-top:6px}table{width:100%;border-collapse:collapse;margin-top:22px;font-size:10px}th,td{padding:7px;border:1px solid #1a3050;text-align:left}th{background:#0f233a;color:#22d3ee}@media print{@page{size:A3 landscape;margin:10mm}}</style></head><body><h1>${escapeHtml(definition.title)} Security Report</h1><div class="meta">Coverage: ${escapeHtml(new Date(report.since).toLocaleString())} → ${escapeHtml(new Date(report.until).toLocaleString())} · ${escapeHtml(categoryLabel)} · ${Number(report.total || 0).toLocaleString()} records${report.truncated ? ' (first 10,000 exported)' : ''}</div><div class="cards">${cards}</div><table><thead><tr>${definition.columns.map(column => `<th>${escapeHtml(column[0])}</th>`).join('')}</tr></thead><tbody>${tableRows || `<tr><td colspan="${definition.columns.length}">No events found</td></tr>`}</tbody></table><script>window.onload=()=>window.print();</script></body></html>`);
    popup.document.close();
  };

  if (!definition) return null;
  return (
    <div style={{ background: COLORS.bg, color: COLORS.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div><h3 style={{ margin: 0, fontSize: 16 }}>📄 {definition.title} Executive Report Generator</h3><div style={{ fontSize: 11, color: COLORS.muted, marginTop: 4 }}>{definition.subtitle}</div></div>
          <button type="button" onClick={generate} disabled={loading} style={{ background: COLORS.cyan, color: '#000', border: 0, padding: '10px 22px', borderRadius: 6, fontWeight: 900, cursor: loading ? 'wait' : 'pointer' }}>{loading ? '⏳ Generating…' : '⚡ Generate Report'}</button>
        </div>
        <div style={{ marginTop: 14, fontSize: 10, color: COLORS.muted, fontWeight: 700 }}>📅 SELECT TIME RANGE</div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 8 }}>
          {PERIODS.map(option => <button key={option.key} type="button" disabled={loading} onClick={() => { setPeriod(option.key); setReport(null); setError(''); }} style={{ minWidth: 100, background: period === option.key ? COLORS.cyan : COLORS.card2, color: period === option.key ? '#000' : COLORS.text, border: `2px solid ${period === option.key ? COLORS.cyan : COLORS.border}`, borderRadius: 8, padding: '9px 16px', cursor: 'pointer', fontWeight: 800 }}><span style={{ fontSize: 17 }}>{option.icon}</span><br />{option.label}</button>)}
        </div>
        <div style={{ marginTop: 14, maxWidth: 340 }}><div style={{ fontSize: 10, color: COLORS.muted, fontWeight: 700, marginBottom: 7 }}>📂 REPORT CATEGORY</div><select value={category} disabled={loading} onChange={event => { setCategory(event.target.value); setReport(null); setError(''); }} style={{ width: '100%', background: COLORS.bg, border: `1px solid ${COLORS.cyan}`, color: COLORS.text, padding: 9, borderRadius: 6 }}>{definition.categories.map(option => <option key={option[0]} value={option[0]}>{option[1]}</option>)}</select></div>
      </div>

      {error && <div style={{ color: COLORS.yellow, background: `${COLORS.yellow}12`, border: `1px solid ${COLORS.yellow}55`, borderRadius: 7, padding: 10, fontSize: 11 }}>{error}</div>}
      {report && <div style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, borderBottom: `1px solid ${COLORS.line}`, paddingBottom: 12 }}>
          <div><div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', fontSize: 14, fontWeight: 800, color: COLORS.cyan }}>📄 {definition.title} — {periodLabel} · {categoryLabel}<span style={{ background: liveConnected ? `${COLORS.green}22` : `${COLORS.yellow}22`, border: `1px solid ${liveConnected ? COLORS.green : COLORS.yellow}`, borderRadius: 999, color: liveConnected ? COLORS.green : COLORS.yellow, fontSize: 9, padding: '2px 7px', letterSpacing: 0.7 }}>{liveConnected ? '● LIVE' : '● LIVE POLLING'}</span></div><div style={{ color: COLORS.muted, fontSize: 10, marginTop: 4 }}>{new Date(report.since).toLocaleString()} → {new Date(report.until).toLocaleString()} · {Number(report.total || 0).toLocaleString()} records · {report.source === 'backend' ? 'Live database' : 'Dashboard fallback'}{lastRefreshedAt ? ` · Updated ${lastRefreshedAt.toLocaleTimeString()}` : ''}</div></div>
          <div style={{ display: 'flex', gap: 8 }}><button type="button" onClick={exportPdf} style={{ background: COLORS.red, color: '#fff', border: 0, padding: '8px 14px', borderRadius: 5, fontWeight: 800 }}>🖨 Export PDF</button><button type="button" onClick={exportCsv} style={{ background: COLORS.green, color: '#000', border: 0, padding: '8px 14px', borderRadius: 5, fontWeight: 800 }}>📥 Export CSV</button><button type="button" onClick={exportJson} style={{ background: COLORS.blue, color: '#000', border: 0, padding: '8px 14px', borderRadius: 5, fontWeight: 800 }}>Export JSON</button></div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(155px, 1fr))', gap: 12 }}>{metricCards.map(([label, value, color]) => <div key={label} style={{ background: COLORS.card2, border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: 13 }}><div style={{ color: COLORS.muted, fontSize: 9, fontWeight: 800 }}>{label}</div><div style={{ color, fontSize: 24, fontWeight: 900, marginTop: 5 }}>{Number(value || 0).toLocaleString()}</div></div>)}</div>
        <div style={{ background: COLORS.card2, border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: 14 }}><div style={{ fontSize: 11, fontWeight: 800, marginBottom: 9 }}>📊 Severity Breakdown</div><div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>{['critical', 'high', 'medium', 'low'].map(level => { const value = Number(report.stats?.bySeverity?.[level] || 0); return <span key={level} style={{ color: { critical: COLORS.red, high: COLORS.orange, medium: COLORS.yellow, low: COLORS.green }[level], textTransform: 'capitalize', fontSize: 11, fontWeight: 800 }}>{level}: {value.toLocaleString()}</span>; })}</div></div>
        <div style={{ overflowX: 'auto', border: `1px solid ${COLORS.border}`, borderRadius: 8 }}><table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}><thead><tr style={{ background: COLORS.card2, color: COLORS.cyan }}>{definition.columns.map(column => <th key={column[0]} style={{ padding: 8, textAlign: 'left', whiteSpace: 'nowrap' }}>{column[0]}</th>)}</tr></thead><tbody>{rows.length ? rows.slice(0, 100).map((row, index) => <tr key={row._id || index} style={{ borderTop: `1px solid ${COLORS.line}` }}>{definition.columns.map(column => <td key={column[0]} style={{ padding: 8, whiteSpace: 'nowrap', maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis' }}>{String(column[1](row) ?? '—')}</td>)}</tr>) : <tr><td colSpan={definition.columns.length} style={{ padding: 28, textAlign: 'center', color: COLORS.muted }}>No events found for this period and category.</td></tr>}</tbody></table></div>
        {rows.length > 100 && <div style={{ fontSize: 10, color: COLORS.muted }}>Preview shows 100 rows; exports contain all {rows.length.toLocaleString()} fetched records.</div>}
      </div>}
    </div>
  );
}
