# SOC Attack Detection & Prevention Capability Report

**Product:** AJNAT SOC / Spartan Cyber Defense Center  
**Assessment type:** Source-code and current configuration review  
**Reviewed endpoint:** `vivo` (Android)  
**Report date:** 29 August 2026

## 1. Executive Summary

AJNAT SOC provides endpoint, network, identity, malware, correlation, incident-response and SOAR capabilities. The platform can detect a wide range of attacks and contains response actions for blocking an IP/domain/port/hash, isolating an endpoint, terminating a process, quarantining a file, locking a user and creating or escalating an incident.

The availability of a feature in the platform does not mean that it is actively preventing attacks on every endpoint. Effective prevention requires a reporting sensor, an enabled policy, a supported enforcement mechanism and, where applicable, an approved SOAR playbook.

For the currently reviewed `vivo` Android endpoint, basic monitoring is active, but automatic attack prevention is not fully configured. The endpoint currently has no active IDS/IPS policy, firewall rule or SOAR automation rule. It also has no packet sensor or inline IPS verdict.

## 2. Current vivo Endpoint Status

| Control | Current status |
|---|---|
| Endpoint online | Yes |
| Operating system | Android |
| Agent version | 0.1.1 |
| EDR enabled | Yes |
| IDS enabled | Yes |
| Endpoint IDS enabled | Yes |
| IPS configured flag | Yes |
| Firewall configured flag | Yes |
| Network monitoring | Yes |
| USB monitoring | Yes |
| Response agent | Yes |
| Packet sensor | No |
| Inline IPS verdict | No |
| IPS enforcement mode | Not configured |
| YARA scanning | Disabled |
| WAF | Disabled |
| Process monitoring | Disabled |
| Memory monitoring | Disabled |
| Enabled IDS/IPS policies | 0 |
| Active firewall rules | 0 |
| Active SOAR rules | 0 |
| Custom correlation rules | 0 |
| Agent integrity status | Unknown |

### Current operational conclusion

The `vivo` endpoint can report supported Android telemetry and generate alerts. However, the current configuration must not be described as guaranteed automatic prevention. Blocking and containment must be configured and tested before being treated as operational.

## 3. Attack Coverage

### 3.1 Malware

The platform supports detection of:

- Malware, trojans, worms, backdoors and rootkit indicators
- Cryptominers and resource hijacking
- Malicious executables, files and hashes
- VirusTotal and threat-intelligence matches
- Obfuscated or masquerading files

Available responses include file quarantine/deletion, hash blocking, process termination, endpoint isolation, network blocking and incident escalation.

**Current vivo position:** Limited. YARA, process monitoring and memory monitoring are disabled.

### 3.2 Ransomware and destructive attacks

The platform can correlate mass file changes, suspicious encryption, malicious execution and related network activity. It also maps ransomware and data-destruction behaviour to incident chains.

Available responses include endpoint isolation, process-tree termination, file quarantine, malicious hash/IP/domain blocking and forensic evidence collection.

**Current vivo position:** Detection may be partial; automated containment is not configured.

### 3.3 Brute force and account takeover

Supported detections include generic brute force, SSH/RDP brute force, repeated failed logins, suspicious root/admin access, impossible travel, account takeover, token hijacking and pass-the-hash indicators.

Available responses include IP blocking, account locking/disabling, session reset, token revocation, forced logoff and escalation.

**Current position:** Detection logic exists, but no active SOAR rule currently automates account or IP containment.

### 3.4 Privilege escalation

The system recognises privilege-escalation exploits, sudo abuse, access-token manipulation, root-login anomalies, unauthorised account creation and privilege activity followed by persistence changes.

Available responses include process termination, account control, token revocation, endpoint isolation, scheduled-task removal and registry rollback.

### 3.5 Malicious scripts and command execution

Supported detections include PowerShell, Windows Command Shell, Bash, WMIC, `mshta`, `regsvr32`, LOLBins, suspicious scripts, reverse shells and unauthorised execution.

Available responses include script termination, process-tree termination, file/hash blocking and endpoint isolation.

**Current vivo position:** Process monitoring is disabled; local execution visibility is therefore limited.

### 3.6 Process injection and memory attacks

The platform contains mappings for process injection, process hollowing, reflective DLL injection, suspicious memory activity, memory overflow, shellcode, Mimikatz and credential dumping.

Available responses include process termination, endpoint isolation and incident escalation.

**Current vivo position:** Process and memory monitoring are disabled.

### 3.7 Network attacks and reconnaissance

Supported detections include port scans, host discovery, malicious connections, known malicious IPs, protocol anomalies, suspicious TLS, malware downloads, exploit kits and reverse-shell traffic.

Available responses include IP/domain/port blocking, firewall deny/drop rules and endpoint isolation.

**Current vivo position:** No packet sensor, inline verdict or active IDS/IPS policy; inline blocking is not active.

### 3.8 Web attacks

Available Suricata policy presets cover:

- SQL injection
- Cross-site scripting (XSS)
- Command injection
- Remote-code execution (RCE)
- Exploit kits
- Malicious HTTP traffic

Possible responses include IP blocking, firewall enforcement and WAF mitigation.

**Current position:** WAF is disabled and no IDS/IPS policy is enabled.

### 3.9 IDS/IPS attacks

Suricata policies support detect/block operation for SQL injection, XSS, command injection, RCE, exploit kits, HTTP attacks, malware/C2 traffic, port scanning, brute force, SSH/RDP brute force, SMB exploits, FTP attacks and DoS signatures.

Zeek policies cover protocol anomalies, DNS tunnelling, botnet C2, beaconing, ARP spoofing, data exfiltration, suspicious TLS and file-transfer observations. Zeek policies are detect-only by design.

**Current position:** There are zero enabled IDS/IPS policies.

### 3.10 Command-and-control and beaconing

The platform detects C2 traffic, periodic beaconing, malware-network chains, DNS-based C2, reverse shells and known threat-intelligence communications.

Available responses include IP/domain blocking, DNS sinkholing, endpoint isolation and process termination.

### 3.11 DNS attacks

Supported detections include DNS tunnelling, malicious DNS traffic, DNS cache-poisoning indicators, DNS integrity changes and C2 over DNS.

Available responses include domain/IP blocking and DNS sinkholing.

**Current position:** Automated DNS containment is not configured.

### 3.12 Lateral movement

The platform maps SMB, PsExec, RDP, remote services, pass-the-hash indicators and multi-system login behaviour.

Available responses include blocking source IPs or ports 445/3389, isolating a compromised endpoint, disabling a user and escalating the case.

### 3.13 Data exfiltration

Supported detections include unusual outbound traffic, data staging, alternate-protocol exfiltration, USB exfiltration, DNS tunnelling and malware-related outbound communications.

Available responses include destination blocking, endpoint isolation, USB blocking and incident escalation.

### 3.14 USB threats

The system supports detection of unauthorised USB insertion, USB autorun malware, removable-media propagation and USB-related data exfiltration.

Available responses include USB blocking, file quarantine, process termination and endpoint isolation.

**Current vivo position:** USB monitoring is enabled, but no automatic USB-blocking playbook is configured.

### 3.15 Persistence

Supported techniques include scheduled tasks, startup entries, Registry Run keys, service creation, autorun, cron modification and backdoor persistence.

Available responses include deleting scheduled tasks/startup entries, rolling back registry changes, stopping services and isolating the endpoint.

Desktop registry and Windows service controls are not directly applicable to Android.

### 3.16 File and registry attacks

The platform supports File Integrity Monitoring, critical-file changes, stored-data manipulation, registry modification and suspicious file-to-execution chains.

Available responses include restoration, quarantine, deletion, hash blocking and registry rollback.

### 3.17 Phishing and email threats

The platform can correlate phishing alerts, suspicious URLs/domains, malicious attachments and email payload execution.

Available responses include URL/domain blocking, file quarantine, session revocation and incident escalation. Direct prevention of email delivery requires an email-security connector or mail gateway integration.

### 3.18 DoS and DDoS

The platform can identify DoS signatures, flooding indicators and DDoS-related anomalies. It can block individual sources or apply local firewall controls.

Large-scale DDoS attacks require upstream protection from an ISP, CDN, Cloudflare or a scrubbing provider. The built-in DDoS preset is detect-only.

### 3.19 Insider threats

Supported signals include unusual user behaviour, unauthorised privilege changes, sensitive-file access, USB exfiltration, data staging, abnormal login time/location and credential misuse.

Available responses include account locking, token/session revocation, USB blocking, endpoint isolation and audit preservation.

### 3.20 Agent tampering and defence evasion

The platform contains self-protection, tamper protection, integrity validation, debugger detection, analysis-tool detection, lockdown and defence-evasion monitoring.

**Current vivo position:** Integrity status is `unknown`; verified integrity evidence is not currently reported.

## 4. Available Response Actions

The platform code supports the following actions, subject to endpoint support, policy and approval:

- Block/unblock IP, domain, port and hash
- Add/remove firewall rules
- Isolate, quarantine, reconnect or release an endpoint
- Kill a process, process tree or child processes
- Quarantine, delete or restore a file
- Block/unblock USB
- Disable/enable/lock a user
- Force logoff and revoke tokens
- Stop, start or restart a service
- Delete scheduled tasks and startup entries
- Roll back registry changes
- Terminate scripts
- Create incidents and tickets
- Notify administrators and SOC staff
- Escalate to L2/L3
- Send email, webhook or API actions through configured connectors

High-risk actions require approval unless an explicitly authorised policy allows otherwise. Endpoint actions are only considered successful after confirmed enforcement; queueing a command is not proof of prevention.

## 5. Detection vs Prevention

| Level | Meaning |
|---|---|
| Detect | The sensor records suspicious activity and creates telemetry or an alert. |
| Correlate | Multiple related events are combined into an attack chain or incident. |
| Contain | The system blocks communication, terminates activity or isolates the endpoint. |
| Prevent | Enforcement stops the malicious action before impact or further spread. |

The SOC must not label a detect-only sensor as prevention. Zeek observations, alerts without enforcement confirmation, queued commands and inactive policies are not proof that an attack was blocked.

## 6. Requirements for Operational Prevention

1. Enable suitable IDS/IPS policies for Suricata-supported traffic.
2. Verify Android-supported firewall or endpoint IPS enforcement.
3. Create SOAR rules and response playbooks.
4. Configure approval requirements for destructive actions.
5. Enable supported YARA, process and memory collectors.
6. Configure WAF controls for protected web applications.
7. Add email, cloud and external-service connectors where required.
8. Verify agent integrity and secure communication.
9. Run controlled detection and blocking tests for every enabled policy.
10. Record agent acknowledgement and enforcement evidence.

## 7. Recommended Priority Plan

### Priority 1 — Immediate

- Enable and test high-confidence Suricata block policies.
- Configure malware, brute-force, C2 and ransomware SOAR workflows.
- Test IP blocking and endpoint isolation on a controlled test asset.
- Verify Android agent command acknowledgement.

### Priority 2 — Visibility

- Enable supported process, memory and YARA telemetry.
- Resolve the endpoint integrity status from `unknown` to `verified`.
- Confirm network and USB event ingestion.

### Priority 3 — Integrations

- Configure WAF, email-security and cloud connectors where applicable.
- Add upstream DDoS protection.
- Configure alert notification and escalation channels.

## 8. Final Assessment

AJNAT SOC has broad attack-detection and response architecture covering malware, ransomware, identity attacks, malicious execution, network attacks, web attacks, DNS threats, lateral movement, data exfiltration, persistence, insider threats and defence evasion.

For the reviewed `vivo` endpoint, the accurate current claim is:

> The SOC can monitor supported Android telemetry and detect selected suspicious activity, but guaranteed automatic prevention is not yet operational because enforcement policies and SOAR automation are not configured.

After policies, sensors and response playbooks are enabled and validated through controlled tests, the platform can provide active containment for supported attacks.

---

**Important:** This report describes verified software capabilities and the reviewed configuration. It is not a guarantee that every attack will be detected or prevented. Coverage depends on sensor support, telemetry quality, policy configuration, agent health and successful enforcement.
