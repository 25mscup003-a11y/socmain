"""Canonical IDS/IPS coverage metadata for the SOC agent.

This is descriptive metadata only. It must not emit alerts by itself.
Actual dashboard counts stay based on real IDS/IPS events.
"""

IDS_IPS_CAPABILITY_GROUPS = [
    {
        "id": "traffic",
        "title": "Traffic Monitoring",
        "capabilities": [
            "Incoming Traffic", "Outgoing Traffic", "Internal Traffic", "Network Packets",
            "TCP Traffic", "UDP Traffic", "ICMP Traffic", "IPv4/IPv6 Traffic",
            "Session Monitoring", "Connection Monitoring",
        ],
    },
    {
        "id": "recon",
        "title": "Network Reconnaissance Detection",
        "capabilities": [
            "Port Scan", "SYN Scan", "FIN Scan", "NULL Scan", "XMAS Scan", "ACK Scan",
            "UDP Scan", "Ping Sweep", "Host Discovery", "Service Enumeration", "Banner Grabbing",
        ],
    },
    {
        "id": "web",
        "title": "Web Application Attack Detection",
        "capabilities": [
            "SQL Injection", "Blind SQL Injection", "XSS", "Stored XSS", "Reflected XSS",
            "CSRF", "Command Injection", "Remote Code Execution (RCE)", "File Upload Attack",
            "Path Traversal", "Directory Traversal", "Local File Inclusion (LFI)",
            "Remote File Inclusion (RFI)", "XXE Attack", "SSRF", "SSTI",
        ],
    },
    {
        "id": "auth",
        "title": "Authentication Attack Detection",
        "capabilities": [
            "Brute Force", "Password Spraying", "Credential Stuffing", "Login Flood",
            "Multiple Failed Login Attempts", "Privilege Escalation Attempts",
        ],
    },
    {
        "id": "malware",
        "title": "Malware Detection",
        "capabilities": [
            "Virus", "Worm", "Trojan", "Spyware", "Rootkit", "Ransomware", "Botnet Traffic",
            "Crypto Miner", "Backdoor", "Malicious Payload",
        ],
    },
    {
        "id": "c2",
        "title": "Command & Control (C2)",
        "capabilities": [
            "HTTP Beaconing", "HTTPS Beaconing", "DNS Tunneling", "Reverse Shell",
            "C2 Communication", "IRC C2", "TOR Traffic",
        ],
    },
    {
        "id": "dos",
        "title": "Denial of Service Detection",
        "capabilities": [
            "DoS Attack", "DDoS Attack", "SYN Flood", "UDP Flood", "ICMP Flood",
            "HTTP Flood", "HTTPS Flood", "Slowloris Attack",
        ],
    },
    {
        "id": "spoofing",
        "title": "Network Spoofing Detection",
        "capabilities": [
            "ARP Spoofing", "ARP Poisoning", "DNS Spoofing", "DNS Cache Poisoning",
            "IP Spoofing", "MAC Spoofing",
        ],
    },
    {
        "id": "protocols",
        "title": "Protocol Monitoring",
        "capabilities": [
            "HTTP", "HTTPS", "DNS", "FTP", "SSH", "SMTP", "POP3", "IMAP",
            "SMB", "LDAP", "SNMP", "RDP", "Telnet",
        ],
    },
    {
        "id": "threat_intel",
        "title": "Threat Intelligence Matching",
        "capabilities": [
            "Malicious IP Detection", "Malicious Domain Detection", "Malicious URL Detection",
            "IOC Matching", "CVE Exploit Detection", "Known Exploit Detection",
            "Signature Match", "Zero-Day Behavior Detection",
        ],
    },
    {
        "id": "anomaly",
        "title": "Anomaly Detection",
        "capabilities": [
            "Unusual Traffic Volume", "Unusual Packet Size", "Suspicious Connection Rate",
            "Unknown Protocol Usage", "Abnormal Network Behavior", "Suspicious Payload",
            "Traffic Spike Detection",
        ],
    },
    {
        "id": "prevention",
        "title": "IPS Prevention Actions",
        "capabilities": [
            "Block Source IP (all supported OS)", "Block Destination IP (all supported OS)",
            "Inline Packet Drop (Linux NFQUEUE)",
            "Reset TCP Session", "Block Port", "Block Protocol", "Block URL",
            "Block Domain", "Quarantine Connection", "Temporary IP Block",
            "Permanent IP Block", "Auto Blacklist",
        ],
    },
    {
        "id": "alert_fields",
        "title": "IDS/IPS Alerts & Logs",
        "capabilities": [
            "Alert ID", "Attack Type", "Threat Severity", "Signature Name", "Source IP",
            "Destination IP", "Source Port", "Destination Port", "Protocol", "Timestamp",
            "Packet Count", "Action (Detected / Blocked)", "Sensor Name", "Rule ID",
            "CVE ID (if available)", "MITRE ATT&CK Mapping (if available)",
        ],
    },
]

IDS_IPS_ATTACK_TYPES = sorted({
    capability
    for group in IDS_IPS_CAPABILITY_GROUPS
    for capability in group["capabilities"]
    if group["id"] not in ("prevention", "alert_fields", "traffic", "protocols")
})
