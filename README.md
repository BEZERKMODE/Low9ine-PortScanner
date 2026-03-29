Low9ine Elite Port Scanner

A high-performance cybersecurity analysis tool that integrates port scanning, vulnerability intelligence, and risk assessment into a real-time interactive dashboard.



0verview

Low9ine Elite Port Scanner is designed to simulate real-world penetration testing workflows by combining multiple scanning techniques with intelligent analysis.

The system goes beyond traditional port scanning by introducing risk scoring, vulnerability mapping, and live visualization, making it suitable for both practical security analysis and advanced learning.

---

Key Highlights

- Multi-mode scanning engine (Async, TCP, SYN)
- Real-time terminal-style scanning output
- CVE-based vulnerability detection
- AI-driven risk scoring system
- Integrated reconnaissance (subdomains, DNS, WHOIS)
- Shodan-based host intelligence
- Interactive analytics dashboard
- Exportable scan reports (CSV and HTML)

---

Architecture

The project follows a modular design separating scanning, analysis, and visualization layers.
Project Structure
PortScanner/
│
├── app.py
├── scanner/
├── utils/
├── requirements.txt
└── README.md

Installation
git clone https://github.com/BEZERKMODE/Low9ine-PortScanner.git
cd Low9ine-PortScanner
pip install -r requirements.txt
streamlit run app.py
Usage
1. Enter target host (IP or domain)
2. Define port range
3. Select scan mode
4. Start scan
5. Analyze results in dashboard
6. Export reports.

Disclaimer

This tool is intended for educational purposes and authorized security testing only. Do not use on systems without permission.
Author
Suraj Bartwal
GitHub: https://github.com/BEZERKMODE