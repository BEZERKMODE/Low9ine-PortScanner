SERVICE_THREAT_DB = {
    "FTP": {
        "threats": [
            "FTP sends credentials in plaintext",
            "Anonymous access and weak credential exposure are common risks",
            "Legacy FTP services are frequently misconfigured"
        ],
        "cvss": 8.1,
        "mitre": ["T1078 - Valid Accounts", "T1040 - Network Sniffing"],
        "simulation": "Exploit Exposure",
        "focus": "Credential Exposure",
    },
    "SSH": {
        "threats": [
            "Weak SSH passwords enable brute-force attempts",
            "Outdated SSH services may expose version-specific weaknesses"
        ],
        "cvss": 6.8,
        "mitre": ["T1110 - Brute Force", "T1021.004 - SSH"],
        "simulation": "Recon",
        "focus": "Remote Access",
    },
    "TELNET": {
        "threats": [
            "Telnet sends credentials and commands in plaintext",
            "Exposed Telnet is high risk on internal and external networks"
        ],
        "cvss": 9.0,
        "mitre": ["T1021 - Remote Services", "T1040 - Network Sniffing"],
        "simulation": "Exploit Exposure",
        "focus": "Credential Exposure",
    },
    "SMTP": {
        "threats": [
            "Open mail services can expose relay or enumeration risk",
            "Misconfigurations may enable user enumeration"
        ],
        "cvss": 5.9,
        "mitre": ["T1589 - Gather Victim Identity Information"],
        "simulation": "Recon",
        "focus": "Service Exposure",
    },
    "DNS": {
        "threats": [
            "DNS exposure may reveal internal records if recursion is open",
            "Zone transfer misconfiguration can leak infrastructure details"
        ],
        "cvss": 6.5,
        "mitre": ["T1590 - Gather Victim Network Information"],
        "simulation": "Recon",
        "focus": "Infrastructure Discovery",
    },
    "HTTP": {
        "threats": [
            "HTTP services may expose outdated web apps and admin panels",
            "Cleartext web traffic increases session and credential exposure"
        ],
        "cvss": 6.1,
        "mitre": ["T1190 - Exploit Public-Facing Application"],
        "simulation": "Recon",
        "focus": "Public Web Exposure",
    },
    "HTTPS": {
        "threats": [
            "HTTPS reduces transport risk but public app exposure still matters",
            "Outdated web stacks and admin panels remain a major attack surface"
        ],
        "cvss": 5.8,
        "mitre": ["T1190 - Exploit Public-Facing Application"],
        "simulation": "Recon",
        "focus": "Public Web Exposure",
    },
    "RPCBIND": {
        "threats": [
            "RPC services can reveal internal network and host details",
            "Often linked to NFS-style lateral movement opportunities"
        ],
        "cvss": 7.2,
        "mitre": ["T1021 - Remote Services"],
        "simulation": "Lateral Movement",
        "focus": "Unix Service Exposure",
    },
    "NETBIOS-NS": {
        "threats": [
            "NetBIOS exposure can reveal hostnames and shares",
            "Legacy Windows naming services increase network visibility"
        ],
        "cvss": 7.3,
        "mitre": ["T1018 - Remote System Discovery"],
        "simulation": "Lateral Movement",
        "focus": "Windows Discovery",
    },
    "NETBIOS-DGM": {
        "threats": [
            "NetBIOS datagram exposure supports Windows host discovery",
            "Often appears alongside risky SMB exposure"
        ],
        "cvss": 7.3,
        "mitre": ["T1018 - Remote System Discovery"],
        "simulation": "Lateral Movement",
        "focus": "Windows Discovery",
    },
    "NETBIOS-SSN": {
        "threats": [
            "NetBIOS session service can support share discovery and access attempts",
            "Often paired with SMB movement risk"
        ],
        "cvss": 7.6,
        "mitre": ["T1021.002 - SMB/Windows Admin Shares"],
        "simulation": "Lateral Movement",
        "focus": "Windows Shares",
    },
    "IMAP": {
        "threats": [
            "Mailbox access services increase credential and data exposure",
            "Weak auth and legacy configs remain common"
        ],
        "cvss": 5.6,
        "mitre": ["T1114 - Email Collection"],
        "simulation": "Recon",
        "focus": "Mailbox Exposure",
    },
    "SNMP": {
        "threats": [
            "Default SNMP community strings can leak network inventory",
            "SNMP often exposes device and interface intelligence"
        ],
        "cvss": 8.0,
        "mitre": ["T1590 - Gather Victim Network Information"],
        "simulation": "Recon",
        "focus": "Network Device Intelligence",
    },
    "LDAP": {
        "threats": [
            "LDAP exposure may leak directory structure and accounts",
            "Directory services are sensitive for identity enumeration"
        ],
        "cvss": 7.4,
        "mitre": ["T1087 - Account Discovery"],
        "simulation": "Recon",
        "focus": "Identity Discovery",
    },
    "SMB": {
        "threats": [
            "SMB exposure strongly increases lateral movement risk",
            "File shares, admin shares, and legacy SMB are high-value targets"
        ],
        "cvss": 9.3,
        "mitre": ["T1021.002 - SMB/Windows Admin Shares", "T1135 - Network Share Discovery"],
        "simulation": "Lateral Movement",
        "focus": "Windows Share Exposure",
    },
    "MSSQL": {
        "threats": [
            "Exposed MSSQL may leak databases and credentials",
            "Database services increase privilege and data theft risk"
        ],
        "cvss": 8.7,
        "mitre": ["T1213 - Data from Information Repositories"],
        "simulation": "Exploit Exposure",
        "focus": "Database Exposure",
    },
    "ORACLE": {
        "threats": [
            "Exposed Oracle services can reveal enterprise data stores",
            "Weak authentication and old listeners are high-value findings"
        ],
        "cvss": 8.9,
        "mitre": ["T1213 - Data from Information Repositories"],
        "simulation": "Exploit Exposure",
        "focus": "Database Exposure",
    },
    "NFS": {
        "threats": [
            "NFS exposure may reveal sensitive mounts and internal data",
            "Weak export policies support lateral movement"
        ],
        "cvss": 8.2,
        "mitre": ["T1021 - Remote Services", "T1105 - Ingress Tool Transfer"],
        "simulation": "Lateral Movement",
        "focus": "Unix Share Exposure",
    },
    "MYSQL": {
        "threats": [
            "Open MySQL may expose application data and weak credentials",
            "Database access often leads to deeper compromise paths"
        ],
        "cvss": 8.8,
        "mitre": ["T1213 - Data from Information Repositories"],
        "simulation": "Exploit Exposure",
        "focus": "Database Exposure",
    },
    "RDP": {
        "threats": [
            "RDP is a major target for brute force and unauthorized remote access",
            "Public RDP exposure is a high-priority hardening issue"
        ],
        "cvss": 9.1,
        "mitre": ["T1021.001 - Remote Desktop Protocol", "T1110 - Brute Force"],
        "simulation": "Lateral Movement",
        "focus": "Remote Admin Exposure",
    },
    "POSTGRESQL": {
        "threats": [
            "Open PostgreSQL may expose business-critical data",
            "Database services increase data theft and privilege escalation paths"
        ],
        "cvss": 8.5,
        "mitre": ["T1213 - Data from Information Repositories"],
        "simulation": "Exploit Exposure",
        "focus": "Database Exposure",
    },
    "VNC": {
        "threats": [
            "VNC provides graphical remote access and is risky if exposed",
            "Weak passwords and no tunneling are common security issues"
        ],
        "cvss": 8.2,
        "mitre": ["T1021 - Remote Services"],
        "simulation": "Lateral Movement",
        "focus": "Remote Desktop Exposure",
    },
    "REDIS": {
        "threats": [
            "Exposed Redis can lead to unauthorized data access",
            "Unauthenticated Redis is a frequent severe misconfiguration"
        ],
        "cvss": 9.0,
        "mitre": ["T1213 - Data from Information Repositories"],
        "simulation": "Exploit Exposure",
        "focus": "In-Memory Database Exposure",
    },
    "HTTP-ALT": {
        "threats": [
            "Alternate web ports often host admin panels or dev services",
            "Non-standard web apps are frequently overlooked during hardening"
        ],
        "cvss": 6.6,
        "mitre": ["T1190 - Exploit Public-Facing Application"],
        "simulation": "Recon",
        "focus": "Alternate Web Surface",
    },
    "HTTPS-ALT": {
        "threats": [
            "Alternate HTTPS ports may expose admin and staging panels",
            "These services increase external application attack surface"
        ],
        "cvss": 6.6,
        "mitre": ["T1190 - Exploit Public-Facing Application"],
        "simulation": "Recon",
        "focus": "Alternate Web Surface",
    },
    "MONGODB": {
        "threats": [
            "Exposed MongoDB has a long history of misconfiguration-related data leaks",
            "Public database access is a critical exposure"
        ],
        "cvss": 9.2,
        "mitre": ["T1213 - Data from Information Repositories"],
        "simulation": "Exploit Exposure",
        "focus": "NoSQL Database Exposure",
    },
    "WINRM-HTTP": {
        "threats": [
            "WinRM exposes Windows remote management interfaces",
            "Management interfaces should be tightly restricted"
        ],
        "cvss": 7.8,
        "mitre": ["T1021.006 - Windows Remote Management"],
        "simulation": "Lateral Movement",
        "focus": "Remote Management Exposure",
    },
    "WINRM-HTTPS": {
        "threats": [
            "WinRM over HTTPS is safer than HTTP but still high-value if exposed",
            "Management plane exposure should remain restricted"
        ],
        "cvss": 7.2,
        "mitre": ["T1021.006 - Windows Remote Management"],
        "simulation": "Lateral Movement",
        "focus": "Remote Management Exposure",
    },
}

DEFAULT_THREAT = {
    "threats": ["Unknown service exposure requires manual validation and hardening review"],
    "cvss": 4.0,
    "mitre": ["T1595 - Active Scanning"],
    "simulation": "Recon",
    "focus": "General Exposure",
}