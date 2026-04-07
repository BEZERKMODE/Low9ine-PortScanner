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
        <tr>
            <td>{row["Port"]}</td>
            <td>{row["Protocol"]}</td>
            <td>{row["Scan"]}</td>
            <td>{row["State"]}</td>
            <td>{row["Service"]}</td>
            <td>{row["Risk"]}</td>
            <td>{row["CVSS"]}</td>
            <td>{row["Simulation"]}</td>
            <td>{row["Focus"]}</td>
            <td>{row["Banner"]}</td>
            <td>{threats}</td>
            <td>{mitre}</td>
        </tr>
        """)

    html_content = f"""
    <html>
    <head>
        <title>Low9ine Report</title>
    </head>
    <body style="background:#05070d;color:#00ffae;font-family:monospace;">
        <h1>LOW9INE ELITE SCAN REPORT</h1>

        <p><b>Target:</b> {target}</p>
        <p><b>IP:</b> {ip}</p>
        <p><b>Mode:</b> {mode_name}</p>
        <p><b>Engine:</b> {engine}</p>
        <p><b>Duration:</b> {duration}s</p>

        <table border="1" cellpadding="5" cellspacing="0">
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
            {''.join(rows)}
        </table>
    </body>
    </html>
    """

    return html_content