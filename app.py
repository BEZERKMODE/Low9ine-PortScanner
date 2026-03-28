import streamlit as st
import socket
import asyncio
import pandas as pd
import plotly.express as px
import time

# SCANNERS
from scanner.async_scanner import scan_ports
from scanner.tcp_scanner import scan_ports_tcp
from scanner.syn_scan import syn_scan

# UTILS
from utils.risk_ports import HIGH_RISK_PORTS
from utils.report import generate_report
from utils.cve_lookup import get_cve
from utils.shodan_lookup import shodan_lookup
from utils.exploit_suggest import suggest_exploit
from utils.bruteforce import simple_bruteforce
from utils.ai_risk import calculate_risk
from utils.recon import run_recon

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="Low9ine Elite Scanner",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------- STYLE ----------------
st.markdown("""
<style>
body { background:#000; color:#00ffcc; font-family: monospace; }

.console {
    background:black;
    padding:10px;
    border-radius:8px;
    max-height:400px;
    overflow-y:auto;
    box-shadow:0 0 10px #00ffcc;
}

.card {
    padding:10px;
    border-radius:10px;
    background:#101430;
    margin-bottom:10px;
}
</style>
""", unsafe_allow_html=True)

# ---------------- SIDEBAR ----------------
st.sidebar.title("⚡ Elite Control Panel")

host = st.sidebar.text_input("🎯 Target", "scanme.nmap.org")
ports = st.sidebar.text_input("📡 Port Range", "20-100")
mode = st.sidebar.selectbox("🛰️ Scan Mode", ["Async", "TCP Connect", "SYN"])

# ---------------- HEADER ----------------
st.title("💀 Low9ine Elite Offensive Toolkit")
st.caption("Recon + Vulnerability + Risk Intelligence Dashboard")

# ---------------- HELPERS ----------------
def resolve(h):
    try:
        return socket.gethostbyname(h)
    except:
        return None

def is_scapy_available():
    try:
        from scapy.all import IP
        return True
    except:
        return False

# ---------------- RECON ----------------
if st.sidebar.button("🔍 Run Recon"):

    recon_data = run_recon(host)

    st.sidebar.subheader("🌐 Subdomains")
    st.sidebar.write(recon_data["subdomains"] or "None found")

    st.sidebar.subheader("📡 DNS Info")
    st.sidebar.json(recon_data["dns"])

    st.sidebar.subheader("📄 WHOIS")
    st.sidebar.text(recon_data["whois"])

    st.sidebar.subheader("🎯 Suggested Ports")
    st.sidebar.write(recon_data["priority_ports"])

# ---------------- SCAN ----------------
if st.button("🚀 Start Scan"):

    ip = resolve(host)

    if not ip:
        st.error("Invalid host")
        st.stop()

    st.info(f"Target IP: {ip}")

    # SHODAN INFO
    try:
        shodan_info = shodan_lookup(ip)
        st.sidebar.success(f"🌐 {shodan_info}")
    except:
        st.sidebar.warning("Shodan lookup failed")

    try:
        start, end = map(int, ports.split("-"))
    except:
        st.error("Invalid port range")
        st.stop()

    plist = list(range(start, end + 1))

    results = []
    console = st.empty()
    progress = st.progress(0)

    console_html = ""

    # ---------------- LIVE SCAN ----------------
    for i, port in enumerate(plist):

        # MODE SELECT
        if mode == "Async":
            res = asyncio.run(scan_ports(ip, [port]))[0]
        elif mode == "TCP Connect":
            res = scan_ports_tcp(ip, [port])[0]
        elif mode == "SYN" and is_scapy_available():
            res = syn_scan(ip, port)
        else:
            res = asyncio.run(scan_ports(ip, [port]))[0]

        p, status = res

        # SERVICE
        service = HIGH_RISK_PORTS.get(p, "unknown")

        # CVE
        cve, severity = get_cve(service)

        # AI RISK
        score, level = calculate_risk(p, status, severity)

        # EXPLOIT (INFO ONLY)
        exploit = suggest_exploit(service, p)

        # ALERT
        if level in ["HIGH", "CRITICAL"]:
            st.error(f"⚠ {service} (Port {p}) → {level} RISK | CVE: {cve}")

        # BRUTEFORCE (SAFE DEMO)
        brute = simple_bruteforce(ip, p) if status == "open" else []

        # SAVE
        results.append({
            "Port": p,
            "Status": status,
            "Service": service,
            "CVE": cve,
            "Severity": severity,
            "Risk Score": score,
            "Risk Level": level,
            "Exploit": exploit,
            "Bruteforce": str(brute)
        })

        # TERMINAL UI
        color = "#00ffcc" if status == "open" else "#ff4c4c"

        console_html += f"<span style='color:{color}'>[+] {p} → {status.upper()} | {service}</span><br>"

        console.markdown(
            f"<div class='console'>{console_html}</div>",
            unsafe_allow_html=True
        )

        progress.progress((i + 1) / len(plist))
        time.sleep(0.01)

    # ---------------- FINAL OUTPUT ----------------
    df = pd.DataFrame(results)

    st.success("Scan Completed")

    col1, col2 = st.columns(2)

    with col1:
        st.dataframe(df)

    with col2:
        try:
            fig = px.pie(df, names="Status", title="Port Distribution")
            st.plotly_chart(fig, use_container_width=True)
        except:
            pass

    # TIMELINE
    try:
        df["Time"] = range(len(df))
        fig2 = px.line(df, x="Time", y="Port", color="Status", title="Scan Timeline")
        st.plotly_chart(fig2)
    except:
        pass

    # ---------------- CSV ----------------
    st.download_button(
        "📥 Download CSV",
        df.to_csv(index=False),
        "scan_results.csv",
        mime="text/csv"
    )

    # ---------------- REPORT ----------------
    report_file = generate_report(results)

    with open(report_file, "rb") as f:
        st.download_button(
            "📄 Download Report",
            f,
            "report.html"
        )