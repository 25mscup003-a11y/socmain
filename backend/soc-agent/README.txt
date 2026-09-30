╔══════════════════════════════════════════════════════════════════╗
║         SOC Agent v0.1.10 — README                              ║
║         Security Monitoring Agent for SOC4 Platform             ║
╚══════════════════════════════════════════════════════════════════╝

WHAT THIS AGENT DOES
─────────────────────
This agent runs silently on your endpoint and:
  • Sends heartbeats every 60 seconds so the SOC dashboard knows the system is Online
  • Monitors file changes (FIM), network connections, running processes, USB devices
  • Detects malware via YARA rules and VirusTotal enrichment
  • Runs EDR — kills malicious processes automatically
  • Runs IDS — detects port scans, C2 connections, brute-force attacks
  • Runs IPS v3.0 — auto-blocks malicious IPs + reports to central IPS server (:5050)
  • IPS Webhook Integration — analyzes payloads for SQLi, XSS, Log4Shell, SSRF, C2 (16 types)
  • Whitelist Engine — never accidentally blocks critical infrastructure
  • Executes dashboard commands: block_ip, isolate, kill_process, quarantine, open/close port
  • Reports all events to your SOC dashboard in real time

QUICK START
────────────
  1. python3 agent.py test        (verify connectivity — no root needed)
  2. sudo python3 agent.py install (install as system service)

COMMANDS
─────────
  python3 agent.py run        # run in foreground (Ctrl+C to stop)
  python3 agent.py test       # connectivity & config test
  sudo python3 agent.py install    # install as OS service
  sudo python3 agent.py uninstall  # remove service
  sudo python3 agent.py start      # start service
  sudo python3 agent.py stop       # stop service
  sudo python3 agent.py status     # check service status

DATA REPORTED TO SERVER (every heartbeat)
──────────────────────────────────────────
  • IP Address       (primary NIC)
  • MAC Address      (primary NIC, used for dedup)
  • Hostname
  • OS Name & Version
  • Agent Version    (v0.1.10)
  • Agent Status     (Online)
  • File, network, process, USB events (as alerts)

Network Activity Monitoring deployment, security prerequisites, defaults,
24-hour dashboard behavior, tests, and rollback guidance are documented in
../../NETWORK_ACTIVITY_MONITORING.md.

Memory Overflow Detection and USB Device Control telemetry, optional OS
providers, least-privilege guidance, configuration, retention, simulation, and
troubleshooting are documented in
../../docs/MEMORY_OVERFLOW_AND_USB_MONITORING.md.

SYSTEM COUNT & LICENSING
──────────────────────────
  • Systems are counted by unique MAC Address OR Agent ID
  • Duplicate MACs are flagged with a warning (not double-counted)
  • If plan limit is reached: new system registration is blocked
  • The dashboard shows: Used / Limit / Remaining

ONLINE / OFFLINE STATUS
────────────────────────
  • System is marked "Online"  if heartbeat received within last 5 minutes (300s)
  • System is marked "Offline" if no heartbeat for > 5 minutes
  • Threshold configurable via env: ONLINE_THRESHOLD_SECONDS=300

CONFIG FILE
────────────
  config/company_config.json — pre-filled when downloaded from dashboard
  Key fields:
    server_url              → SOC backend URL
    agent_key               → unique per-system authentication key
    heartbeat_interval_seconds → default 60
    edr_enabled             → true/false
    ids_enabled             → true/false
    ips_enabled             → true/false
    firewall_enabled        → true/false

LOG LOCATIONS
──────────────
  Linux:   /var/log/soc-agent/agent.log      (rotates at 10 MB, 5 backups)
  Windows: C:\ProgramData\SOCAgent\logs\agent.log
  macOS:   /Library/Logs/SOCAgent/agent.log
  Android: $HOME/.soc-agent/logs/agent.log
  No source-tree log fallback is created.

SUPPORTED PLATFORMS
────────────────────
  ✅ Linux   — Debian, Ubuntu, Kali, Mint, RHEL, CentOS, Fedora, Rocky
  ✅ Windows — 10, 11, Server 2016+
  ✅ macOS   — 12 Monterey and later
  ✅ Android — native APK from Download Agent

REQUIREMENTS
─────────────
  Python 3.8+
  pip packages: see requirements.txt
  Root/Admin:   required for service install, IPS/Firewall rules

WINDOWS / WINDOWS SERVER INLINE IPS
───────────────────────────────────
  Windows inline packet verdicts use Suricata compiled with WinDivert support.
  Npcap capture is IDS-only and is not used for this mode. The installer checks
  `suricata.exe --build-info` for `WinDivert enabled: yes` and refuses to report
  inline IPS when that capability or the adjacent WinDivert DLL/driver is absent.

  For an AJNAT-signed WinDivert-enabled Suricata MSI/EXE, set:
    AJNAT_SURICATA_INSTALLER_URL=https://.../suricata-windivert.msi
    AJNAT_SURICATA_INSTALLER_SHA256=<sha256>

  Endpoint/server protection uses the WinDivert NETWORK layer by default. A
  Windows gateway protecting forwarded traffic can run install-windows-ids.ps1
  with -ForwardTraffic. AJNAT_SURICATA_WINDIVERT_FILTER can narrow the default
  `true` filter. Suricata drop/reject rules enforce inline; Defender Firewall
  keeps longer-lived source-IP blocks after alerts.

ADVANCED PROCESS TELEMETRY
──────────────────────────
  All desktop/server agents inventory services, scheduled jobs, startup entries,
  application/database workloads, process sockets, and available Docker, Podman,
  and Kubernetes workloads. Common web/database logs are monitored from their
  native locations when the service account has read permission.

  Windows installers enable native Process Creation audit policy, command-line
  auditing, PowerShell Script Block Logging, and Task Scheduler Operational logs.
  DLL injection, remote-thread injection, process access, process hollowing and
  exact process-to-DNS attribution require Microsoft Sysmon. If Sysmon64.exe is
  already installed, or is staged at tools\Sysmon64.exe, the installer applies
  sysmon-ajnat.xml. Without Sysmon, the dashboard reports DEGRADED coverage; it
  never labels polling or command-line heuristics as kernel evidence.

SUPPORT
────────
  See INSTALL.txt for full installation steps per OS.
  Run: python3 agent.py test   — for self-diagnosis.
