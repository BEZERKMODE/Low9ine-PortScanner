# utils/report.py

def generate_report(results):
    """
    Generate HTML pentest report
    """

    html = """
    <html>
    <head>
    <title>Low9ine Scan Report</title>
    <style>
        body { background:#0c0f1a; color:#dcdcdc; font-family: monospace; }
        h1 { color:#00ffcc; }
        table { width:100%; border-collapse: collapse; }
        th, td { padding:8px; border:1px solid #333; text-align:center; }
        th { background:#101430; }
        .high { background:#ff4c4c; color:white; }
        .medium { background:#ff9800; color:black; }
        .low { background:#4caf50; color:white; }
    </style>
    </head>
    <body>

    <h1>🛡️ Low9ine Security Scan Report</h1>
    <table>
    <tr>
        <th>Port</th>
        <th>Status</th>
        <th>Service</th>
        <th>CVE</th>
        <th>Severity</th>
        <th>Risk Score</th>
        <th>Risk Level</th>
    </tr>
    """

    for row in results:

        # ✅ FIXED FIELD NAME
        risk_level = row.get("Risk Level", "LOW")

        if risk_level == "CRITICAL" or risk_level == "HIGH":
            risk_class = "high"
        elif risk_level == "MEDIUM":
            risk_class = "medium"
        else:
            risk_class = "low"

        html += f"""
        <tr class="{risk_class}">
            <td>{row.get("Port","")}</td>
            <td>{row.get("Status","")}</td>
            <td>{row.get("Service","")}</td>
            <td>{row.get("CVE","")}</td>
            <td>{row.get("Severity","")}</td>
            <td>{row.get("Risk Score","")}</td>
            <td>{risk_level}</td>
        </tr>
        """

    html += """
    </table>
    </body>
    </html>
    """

    file_name = "report.html"

    with open(file_name, "w", encoding="utf-8") as f:
        f.write(html)

    return file_name