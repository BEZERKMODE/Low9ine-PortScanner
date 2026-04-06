from datetime import datetime
import os
from typing import TypedDict


class ScanResult(TypedDict):
    port: int
    status: str
    service: str
    banner: str
    risk: str


def generate_report(results: list[ScanResult]) -> str:
    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_name = os.path.join(reports_dir, f"low9ine_report_{timestamp}.html")

    rows = ""
    for result in results:
        port = result["port"]
        status = result["status"]
        service = result["service"]
        banner = result["banner"]
        risk = result["risk"]

        risk_class = "low"
        if risk.lower() == "high":
            risk_class = "high"
        elif risk.lower() == "medium":
            risk_class = "medium"
        elif risk.lower() == "critical":
            risk_class = "critical"

        rows += f"""
        <tr class="{risk_class}">
            <td>{port}</td>
            <td>{status}</td>
            <td>{service}</td>
            <td>{banner}</td>
            <td>{risk}</td>
        </tr>
        """

    html = f"""
    <html>
    <head>
        <title>Low9ine Scan Report</title>
        <style>
            body {{
                background: #0c0f1a;
                color: #dcdcdc;
                font-family: Arial, sans-serif;
                padding: 20px;
            }}
            h1 {{
                color: #00ffcc;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }}
            th, td {{
                padding: 10px;
                border: 1px solid #333;
                text-align: center;
            }}
            th {{
                background: #101430;
                color: #00ffcc;
            }}
            tr:nth-child(even) {{
                background: #14192b;
            }}
            .low {{
                background-color: #1a2d1a;
            }}
            .medium {{
                background-color: #3a3200;
            }}
            .high {{
                background-color: #4a1a1a;
            }}
            .critical {{
                background-color: #660000;
                color: white;
                font-weight: bold;
            }}
        </style>
    </head>
    <body>
        <h1>Low9ine Port Scanner Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

        <table>
            <tr>
                <th>Port</th>
                <th>Status</th>
                <th>Service</th>
                <th>Banner</th>
                <th>Risk</th>
            </tr>
            {rows}
        </table>
    </body>
    </html>
    """

    with open(file_name, "w", encoding="utf-8") as file:
        file.write(html)

    return file_name