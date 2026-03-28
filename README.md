# Low9ine Port Scanner

A live, hacker-style port scanner dashboard built with Streamlit.

## Features
- Multi-threaded scanning
- Live terminal-style console
- High-risk port alerts
- Top 10 vulnerable ports highlighted
- Live table & chart of scanned ports
- Export results to CSV
- Live cybersecurity news feed

## Usage
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   
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