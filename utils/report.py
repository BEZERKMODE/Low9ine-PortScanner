import asyncio
import socket
import time

import pandas as pd
import plotly.express as px
import streamlit as st

# SCANNERS
from scanner.async_scanner import scan_ports
from scanner.tcp_scanner import scan_ports_tcp
from scanner.syn_scan import syn_scan

# UTILS
from utils.ai_risk import calculate_risk
from utils.bruteforce import simple_bruteforce
from utils.cve_lookup import get_cve
from utils.exploit_suggest import suggest_exploit
from utils.recon import run_recon
from utils.report import generate_report
from utils.risk_ports import HIGH_RISK_PORTS
from utils.shodan_lookup import shodan_lookup


# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="Low9ine Elite Scanner",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------- CUSTOM STYLE ----------------
st.markdown("""
<style>
body {
    background-color: #000000;
    color: #00ffcc;
    font-family: monospace;
}

.console {
    background: #000000;
    padding: 12px;
    border-radius: 10px;
    max-height: 400px;
    overflow-y: auto;
    box-shadow: 0 0 12px #00ffcc;
    border: 1px solid #1f2937;
}

.block-card {
    background: #101430;
    padding: 14px;
    border-radius: 12px;
    border: 1px solid #1f2937;
    margin-bottom: 10px;
}
</style>
""", unsafe_allow_html=True)

# ---------------- HELPERS ----------------
def resolve_host(hostname: str):
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def is_scapy_available():
    try:
        from scapy.all import IP  # noqa: F401
        return True
    except Exception:
        return False


def parse_port_range(port_range: str):
    try:
        start_port, end_port = map(int, port_range.split("-"))
        if start_port < 0 or end_port > 65535 or start_port > end_port:
            return None, None
        return start_port, end_port
    except Exception:
        return None, None


def run_single_port_scan(ip: str, port: int, mode: str):
    if mode == "Async":
        return asyncio.run(scan_ports(ip, [port]))[0]
    if mode == "TCP Connect":
        return scan_ports_tcp(ip, [port])[0]
    if mode == "SYN":
        if is_scapy_available():
            return syn_scan(ip, port)
        return asyncio.run(scan_ports(ip, [port]))[0]
    return asyncio.run(scan_ports(ip, [port]))[0]


# ---------------- SIDEBAR ----------------
st.sidebar.title("⚡ Elite Control Panel")

host = st.sidebar.text_input("🎯 Target", "scanme.nmap.org")
ports = st.sidebar.text_input("📡 Port Range", "20-100")
mode = st.sidebar.selectbox("🛰️ Scan Mode", ["Async", "TCP Connect", "SYN"])

# ---------------- HEADER ----------------
st.title("💀 Low9ine Elite Offensive Toolkit")
st.caption("Recon + Vulnerability + Risk Intelligence Dashboard")

# ---------------- RECON ----------------
if st.sidebar.button("🔍 Run Recon"):
    try:
        recon_data = run_recon(host)

        st.sidebar.subheader("🌐 Subdomains")
        st.sidebar.write(recon_data.get("subdomains") or "None found")

        st.sidebar.subheader("📡 DNS Info")
        st.sidebar.json(recon_data.get("dns", {}))

        st.sidebar.subheader("📄 WHOIS")
        st.sidebar.text(recon_data.get("whois", "No WHOIS data"))

        st.sidebar.subheader("🎯 Suggested Ports")
        st.sidebar.write(recon_data.get("priority_ports", []))
    except Exception as e:
        st.sidebar.error(f"Recon failed: {e}")

# ---------------- START SCAN ----------------
if st.button("🚀 Start Scan"):
    ip = resolve_host(host)

    if not ip:
        st.error("Invalid host. Enter a valid domain or IP address.")
        st.stop()

    st.info(f"Target IP: {ip}")

    # SHODAN LOOKUP
    try:
        shodan_info = shodan_lookup(ip)
        st.sidebar.success(f"🌐 {shodan_info}")
    except Exception:
        st.sidebar.warning("Shodan lookup failed")

    # PORT RANGE
    start_port, end_port = parse_port_range(ports)
    if start_port is None or end_port is None:
        st.error("Invalid port range. Use format like 20-100")
        st.stop()

    port_list = list(range(start_port, end_port + 1))

    results = []
    console_box = st.empty()
    progress_bar = st.progress(0)
    console_html = ""

    # ---------------- LIVE SCAN LOOP ----------------
    for index, port in enumerate(port_list):
        try:
            scan_result = run_single_port_scan(ip, port, mode)

            # expected format: (port, status)
            scanned_port, status = scan_result

            service = HIGH_RISK_PORTS.get(scanned_port, "unknown")
            cve, severity = get_cve(service)
            risk_score, risk_level = calculate_risk(scanned_port, status, severity)
            exploit = suggest_exploit(service, scanned_port)

            if risk_level in ["HIGH", "CRITICAL"]:
                st.error(f"⚠ {service} (Port {scanned_port}) → {risk_level} RISK | CVE: {cve}")

            brute = simple_bruteforce(ip, scanned_port) if status == "open" else []

            results.append({
                "Port": scanned_port,
                "Status": status,
                "Service": service,
                "CVE": cve,
                "Severity": severity,
                "Risk Score": risk_score,
                "Risk Level": risk_level,
                "Exploit": exploit,
                "Bruteforce": str(brute)
            })

            line_color = "#00ffcc" if status == "open" else "#ff4c4c"
            console_html += (
                f"<span style='color:{line_color}'>"
                f"[+] {scanned_port} → {status.upper()} | {service}"
                f"</span><br>"
            )

            console_box.markdown(
                f"<div class='console'>{console_html}</div>",
                unsafe_allow_html=True
            )

        except Exception as e:
            results.append({
                "Port": port,
                "Status": "error",
                "Service": "unknown",
                "CVE": "N/A",
                "Severity": "LOW",
                "Risk Score": 0,
                "Risk Level": "LOW",
                "Exploit": "N/A",
                "Bruteforce": "[]"
            })

            console_html += (
                f"<span style='color:#ff4c4c'>"
                f"[!] {port} → ERROR | {e}"
                f"</span><br>"
            )

            console_box.markdown(
                f"<div class='console'>{console_html}</div>",
                unsafe_allow_html=True
            )

        progress_bar.progress((index + 1) / len(port_list))
        time.sleep(0.01)

    # ---------------- RESULTS DATAFRAME ----------------
    df = pd.DataFrame(results)

    st.success("✅ Scan Completed")

    # ---------------- METRICS ----------------
    open_count = len(df[df["Status"] == "open"])
    filtered_count = len(df[df["Status"] == "filtered"])
    closed_count = len(df[df["Status"] == "closed"])

    metric_col1, metric_col2, metric_col3 = st.columns(3)
    metric_col1.metric("Open Ports", open_count)
    metric_col2.metric("Filtered Ports", filtered_count)
    metric_col3.metric("Closed Ports", closed_count)

    # ---------------- TABLE + PIE CHART ----------------
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📋 Scan Results")
        st.dataframe(df, width="stretch")

    with col2:
        st.subheader("📊 Port Status Distribution")
        status_counts = df["Status"].value_counts().reset_index()
        status_counts.columns = ["Status", "Count"]

        pie_fig = px.pie(
            status_counts,
            names="Status",
            values="Count",
            title="Port Status Distribution",
            hole=0.4
        )
        st.plotly_chart(pie_fig, width="stretch")

    # ---------------- TIMELINE CHART ----------------
    st.subheader("📈 Scan Timeline")
    df["Time"] = range(len(df))
    line_fig = px.line(
        df,
        x="Time",
        y="Port",
        color="Status",
        title="Scan Timeline"
    )
    st.plotly_chart(line_fig, width="stretch")

    # ---------------- CSV DOWNLOAD ----------------
    csv_data = df.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="📥 Download CSV Report",
        data=csv_data,
        file_name="low9ine_scan_results.csv",
        mime="text/csv"
    )

    # ---------------- HTML REPORT DOWNLOAD ----------------
    try:
        report_file = generate_report(results)
        with open(report_file, "rb") as f:
            st.download_button(
                label="📄 Download HTML Report",
                data=f,
                file_name="low9ine_report.html",
                mime="text/html"
            )
    except Exception as e:
        st.warning(f"Report generation failed: {e}")