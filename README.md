# 💀 Low9ine Elite Port Scanner

Advanced cybersecurity scanning tool built with Python & Streamlit.

## 🚀 Features
- Async + TCP + SYN scanning
- CVE vulnerability detection
- AI-based risk scoring
- Recon (subdomains + DNS)
- Shodan integration
- Live hacker-style terminal UI
- CSV + Report download

## 🛠️ Installation

```bash
pip install -r requirements.txt
streamlit run app.py
   
---

## 6️⃣ Export Scan Results Folder

Create a folder called `scans/` to save CSV results.  
Modify your code to save scans automatically:

```python
import os
if not os.path.exists("scans"):
    os.makedirs("scans")

file_path = f"scans/Low9ine_scan_{host_input}.csv"
df_final.to_csv(file_path, index=False)
# Low9ine-PortScanner
# Low9ine Port Scanner  A live, hacker-style port scanner dashboard built with Streamlit.  ## Features - Multi-threaded scanning - Live terminal-style console - High-risk port alerts - Top 10 vulnerable ports highlighted - Live table &amp; chart of scanned ports -
Disclaimer

This tool is for educational and ethical testing only.


---

# 📸 2. ADD SCREENSHOT (BIG UPGRADE)

1. Run your app
2. Take screenshot
3. Save as:
```text
screenshot.png
