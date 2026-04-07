import json
import html


def generate_json_report(results):
    return json.dumps(results, indent=2)


def generate_html_report(df, target, ip, mode_name, engine, duration):
    rows = []

    for _, row in df.iterrows():
        threats = "<br>".join([html.escape(str(x)) for x in row["Threats"]]) if row["Threats"] else ""
        mitre = "<br>".join([html.escape(str(x)) for x in row["MITRE"]]) if row["MITRE"] else ""

        rows.append(f"""
        <tr class="{str(row["Risk"]).lower()}">
            <td>{row["Port"]}</td>
            <td>{html.escape(str(row["Protocol"]))}</td>
            <td>{html.escape(str(row["Scan"]))}</td>
            <td>{html.escape(str(row["State"]))}</td>
            <td>{html.escape(str(row["Service"]))}</td>
            <td>{html.escape(str(row["Risk"]))}</td>
            <td>{html.escape(str(row["CVSS"]))}</td>
            <td>{html.escape(str(row["Simulation"]))}</td>
            <td>{html.escape(str(row["Focus"]))}</td>
            <td>{html.escape(str(row["Banner"]))}</td>
            <td>{threats}</td>
            <td>{mitre}</td>
        </tr>
        """)

    rows_html = "\n".join(rows)

    html_report = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8"/>
        <title>Low9ine Elite Report</title>
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
            .panel {{
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
                font-size: 12px;
            }}
            th, td {{
                border: 1px solid #1f334a;
                padding: 8px;
                text-align: left;
                vertical-align: top;
            }}
            th {{
                background: #101b2f;
                color: #00e7ff;
            }}
            tr.critical {{
                background: rgba(255, 0, 0, 0.18);
            }}
            tr.high {{
                background: rgba(255, 120, 0, 0.12);
            }}
            tr.medium {{
                background: rgba(255, 200, 0, 0.08);
            }}
            tr.low {{
                background: rgba(0, 255, 174, 0.05);
            }}
        </style>
    </head>
    <body>
        <h1>LOW9INE ELITE SCANNER REPORT</h1>

        <div class="panel">
            <p><strong>Target:</strong> {html.escape(str(target))}</p>
            <p><strong>Resolved IP:</strong> {html.escape(str(ip))}</p>
            <p><strong>Mode:</strong> {html.escape(str(mode_name))}</p>
            <p><strong>Engine:</strong> {html.escape(str(engine))}</p>
            <p><strong>Duration:</strong> {html.escape(str(duration))} seconds</p>
            <p><strong>Total Findings:</strong> {len(df)}</p>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Scan</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Risk</th>
                    <th>CVSS</th>
                    <th>Simulation</th>
                    <th>Focus</th>
                    <th>Banner</th>
                    <th>Threats</th>
                    <th>MITRE</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
    </body>
    </html>
    """
    return html_report