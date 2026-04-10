# LOW9INE ELITE SCANNER

Network Exposure • Threat Intelligence • Live Recon Dashboard

---

## Overview

Low9ine Elite Scanner is a Python-based network scanning and threat analysis tool designed to simulate real-world penetration testing workflows.

It combines high-speed port scanning with offline threat intelligence, CVSS scoring, and MITRE ATT&CK mapping to provide meaningful security insights beyond basic enumeration.

---

## Key Features

### Multi-Engine Scan System

Supports multiple scan techniques:

* TCP Connect Scan
* UDP Probe Scan
* SYN Scan (simulated)
* ACK Scan
* Window Scan
* Banner Grabbing Scan

---

### Advanced Scan Modes (Preset-Based)

Organized scan presets inspired by professional tools:

* Quick Scan
* Top 100 / Top 1000 Ports
* Full Scan (1–65535)
* Web Scan / Web Extended
* Windows / Linux Audit
* Database Scan
* High Risk Ports
* Docker / Kubernetes
* IoT Scan
* Remote Access
* Custom Mode

---

### Threat Intelligence (Offline)

* CVE-style vulnerability insights
* CVSS-based risk scoring
* MITRE ATT&CK technique mapping
* Attack simulation labels:

  * Recon
  * Exploit Exposure
  * Lateral Movement

---

### Live Dashboard

* Real-time scan results
* Live terminal-style logs
* Progress tracking
* Interactive tables

---

### Visualization

* State distribution (Open / Closed / Filtered)
* Risk distribution (Low / Medium / High / Critical)

---

### Export Options

* CSV report
* JSON report
* HTML pentest report

---

## Project Structure

```
Low9ine-PortScanner/
│
├── app.py
├── requirements.txt
│
├── scanner/
│   ├── basic_scans.py
│   ├── discovery.py
│   └── fingerprint.py
│
├── intelligence/
│   ├── cve_db.py
│   └── risk_ai.py
│
└── utils/
    ├── helpers.py
    ├── exporter.py
    └── scan_modes.py
```

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/Low9ine-PortScanner.git
cd Low9ine-PortScanner
pip install -r requirements.txt
```

---

## Usage

```bash
streamlit run app.py
```

Open in browser:

```
http://localhost:8501
```

---

## Example Workflow

1. Select Mode Category and Scan Mode
2. Enter target (IP or domain)
3. Choose scan engine
4. Start scan
5. Monitor live results and logs
6. Export report

---

## Learning Outcomes

* Network scanning fundamentals
* Socket programming in Python
* Concurrent execution (threading)
* Service detection and banner grabbing
* Risk scoring and threat modeling
* Building real-world cybersecurity tools

---

## Use Cases

* Network reconnaissance
* Security auditing (basic level)
* Cybersecurity learning projects
* Portfolio demonstration

---

## Disclaimer

This tool is intended for educational purposes and authorized testing only.
Do not use it on systems without permission.

---

## Author

Suraj Bartwal
B.Tech Computer Science (Cybersecurity)

---

## Future Improvements

* Real SYN scan using raw packets
* OS fingerprinting
* AI-based anomaly detection
* SIEM / SOC dashboard integration
* Cloud deployment

---

## License

This project is for educational use.
