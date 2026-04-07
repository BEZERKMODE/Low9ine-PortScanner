SCAN_MODES = {
    "Quick Scan": {
        "ports": "21,22,23,25,53,80,110,139,143,443,445,3389",
        "description": "Fast recon on common high-value ports.",
        "simulation": "Recon",
        "focus": "Initial Surface Mapping",
    },
    "Top 100 Ports": {
        "ports": "1-100",
        "description": "Short-range sweep for quick visibility.",
        "simulation": "Recon",
        "focus": "Rapid Coverage",
    },
    "Top 1000 Ports": {
        "ports": "1-1000",
        "description": "Broader baseline audit similar to common scanner defaults.",
        "simulation": "Recon",
        "focus": "Baseline Coverage",
    },
    "Full Scan (1-65535)": {
        "ports": "1-65535",
        "description": "Complete sweep of all port numbers.",
        "simulation": "Recon",
        "focus": "Maximum Coverage",
    },
    "Web Scan": {
        "ports": "80,443,8080,8000,8443,8888",
        "description": "Web services and alternate application ports.",
        "simulation": "Recon",
        "focus": "Public Web Exposure",
    },
    "Web Extended": {
        "ports": "80,443,3000,5000,7001,8000,8080,8443,8888,9000",
        "description": "Web, admin, staging, and development services.",
        "simulation": "Exploit Exposure",
        "focus": "App / Admin Panels",
    },
    "Windows Audit": {
        "ports": "135,137,138,139,445,3389,5985,5986",
        "description": "Windows remote access, SMB, and management surfaces.",
        "simulation": "Lateral Movement",
        "focus": "Windows Admin Exposure",
    },
    "Linux Audit": {
        "ports": "21,22,25,53,80,111,443,631,2049",
        "description": "Linux and Unix service exposure checks.",
        "simulation": "Lateral Movement",
        "focus": "Unix Service Exposure",
    },
    "Database Scan": {
        "ports": "1433,1521,3306,5432,6379,27017",
        "description": "Structured and NoSQL database attack surface audit.",
        "simulation": "Exploit Exposure",
        "focus": "Database Exposure",
    },
    "Mail Scan": {
        "ports": "25,110,143,465,587,993,995",
        "description": "Mail protocol visibility and mailbox service review.",
        "simulation": "Recon",
        "focus": "Mail Surface",
    },
    "Remote Access": {
        "ports": "22,23,3389,5900,5985,5986",
        "description": "Remote login and admin protocols.",
        "simulation": "Lateral Movement",
        "focus": "Remote Admin Exposure",
    },
    "Network Devices": {
        "ports": "22,23,80,161,443,8080",
        "description": "Routers, switches, printers, and appliance interfaces.",
        "simulation": "Recon",
        "focus": "Infrastructure Discovery",
    },
    "High Risk Ports": {
        "ports": "21,23,135,137,138,139,445,1433,1521,3306,3389,5900,6379,27017",
        "description": "High-priority misconfiguration and exposure targets.",
        "simulation": "Exploit Exposure",
        "focus": "High Severity Services",
    },
    "Docker / Kubernetes": {
        "ports": "2375,2376,6443,10250",
        "description": "Container and orchestration plane exposure checks.",
        "simulation": "Exploit Exposure",
        "focus": "Container Control Plane",
    },
    "IoT Scan": {
        "ports": "23,80,443,1883,5683",
        "description": "Common smart-device, MQTT, and CoAP surfaces.",
        "simulation": "Exploit Exposure",
        "focus": "Embedded Exposure",
    },
    "Custom": {
        "ports": "",
        "description": "Manually define your own range or list.",
        "simulation": "Recon",
        "focus": "Custom Coverage",
    },
}

SCAN_MODE_GROUPS = {
    "Core": {
        "Quick Scan": SCAN_MODES["Quick Scan"],
        "Top 100 Ports": SCAN_MODES["Top 100 Ports"],
        "Top 1000 Ports": SCAN_MODES["Top 1000 Ports"],
        "Full Scan (1-65535)": SCAN_MODES["Full Scan (1-65535)"],
        "Custom": SCAN_MODES["Custom"],
    },
    "Web & App": {
        "Web Scan": SCAN_MODES["Web Scan"],
        "Web Extended": SCAN_MODES["Web Extended"],
    },
    "Infrastructure": {
        "Windows Audit": SCAN_MODES["Windows Audit"],
        "Linux Audit": SCAN_MODES["Linux Audit"],
        "Network Devices": SCAN_MODES["Network Devices"],
        "Docker / Kubernetes": SCAN_MODES["Docker / Kubernetes"],
    },
    "Data & Access": {
        "Database Scan": SCAN_MODES["Database Scan"],
        "Mail Scan": SCAN_MODES["Mail Scan"],
        "Remote Access": SCAN_MODES["Remote Access"],
        "High Risk Ports": SCAN_MODES["High Risk Ports"],
        "IoT Scan": SCAN_MODES["IoT Scan"],
    },
}