def generate_html_report(df, target, target_ip, scan_type, duration):
    rows = []

    for _, row in df.iterrows():
        risk_class = str(row["Risk"]).lower()
        state_class = str(row["State"]).lower().replace("|", "-").replace(" ", "-")

        rows.append(f"""
        <tr class="{risk_class}">
            <td>{row["Port"]}</td>
            <td>{row["Protocol"]}</td>
            <td>{row["Scan Type"]}</td>
            <td>{row["State"]}</td>
            <td>{row["Service"]}</td>
            <td>{row["Risk"]}</td>
            <td>{row["Banner"]}</td>
        </tr>
        """)

    rows_html = "\n".join(rows)

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Low9ine Scan Report</title>
        <style>
            body {{
                background: #05070d;
                color: #d7ffe8;
                font-family: Consolas, monospace;
                padding: 24px;
            }}
            h1 {{
                color: #00ffae;
            }}
            .meta {{
                background: #0b1220;
                border: 1px solid rgba(0,255,174,0.18);
                border-radius: 16px;
                padding: 16px;
                margin-bottom: 20px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                background: #09111d;
            }}
            th, td {{
                border: 1px solid #1f334a;
                padding: 10px;
                text-align: center;
                font-size: 13px;
            }}
            th {{
                background: #101b2f;
                color: #00e7ff;
            }}
            tr.high {{
                background: rgba(255, 0, 0, 0.10);
            }}
            tr.medium {{
                background: rgba(255, 165, 0, 0.08);
            }}
            tr.low {{
                background: rgba(0, 255, 174, 0.05);
            }}
        </style>
    </head>
    <body>
        <h1>LOW9INE ELITE PORT SCANNER REPORT</h1>

        <div class="meta">
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Resolved IP:</strong> {target_ip}</p>
            <p><strong>Scan Type:</strong> {scan_type}</p>
            <p><strong>Duration:</strong> {duration} seconds</p>
            <p><strong>Total Results:</strong> {len(df)}</p>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Scan Type</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Risk</th>
                    <th>Banner</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
    </body>
    </html>
    """
    return html