import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
import plotly.express as px
import streamlit as st

from scanner.basic_scans import (
    tcp_connect_scan,
    udp_probe_scan,
    syn_scan,
    ack_scan,
    window_scan,
    banner_scan,
)
from scanner.discovery import is_host_reachable_tcp
from utils.helpers import (
    resolve_target,
    validate_target,
    parse_ports,
    summarize_findings,
)
from utils.exporter import generate_html_report, generate_json_report
from utils.scan_modes import SCAN_MODE_GROUPS

st.set_page_config(
    page_title="LOW9INE ELITE SCANNER",
    page_icon=None,
    layout="wide",
)

if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

if "live_logs" not in st.session_state:
    st.session_state.live_logs = []

SCAN_FUNCTIONS = {
    "TCP Connect": tcp_connect_scan,
    "UDP Probe": udp_probe_scan,
    "SYN Scan (Simulated)": syn_scan,
    "ACK Scan": ack_scan,
    "Window Scan": window_scan,
    "Banner Scan": banner_scan,
}

SCAN_DESC = {
    "TCP Connect": "Full TCP handshake scan",
    "UDP Probe": "Basic UDP service probe",
    "SYN Scan (Simulated)": "Stealth-style scan using safe socket logic",
    "ACK Scan": "Connection-response based firewall visibility check",
    "Window Scan": "Advanced TCP-style response analysis",
    "Banner Scan": "Deep service fingerprinting with banner collection",
}

st.markdown("""
<style>
html, body, [class*="css"] {
    background: #03060d;
    color: #d7ffe8;
    font-family: Consolas, monospace;
}

.stApp {
    background:
        radial-gradient(circle at 12% 10%, rgba(0,255,170,0.10), transparent 20%),
        radial-gradient(circle at 88% 16%, rgba(0,195,255,0.10), transparent 20%),
        radial-gradient(circle at 50% 78%, rgba(0,255,120,0.05), transparent 22%),
        linear-gradient(180deg, #02050b 0%, #06101d 45%, #08111f 100%);
}

.block-container {
    padding-top: 2.2rem !important;
    padding-bottom: 2rem;
    max-width: 1500px;
}

header[data-testid="stHeader"] {
    background: rgba(0,0,0,0);
}

section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #050913 0%, #081120 100%);
    border-right: 1px solid rgba(0,255,174,0.10);
}

section[data-testid="stSidebar"] * {
    color: #d7ffe8 !important;
}

.main-title {
    font-size: 3rem;
    font-weight: 900;
    letter-spacing: 2px;
    color: #00ffae;
    text-shadow:
        0 0 6px rgba(0,255,174,0.55),
        0 0 16px rgba(0,255,174,0.35),
        0 0 28px rgba(0,217,255,0.18);
    margin-bottom: 0.15rem;
    line-height: 1.1;
}

.sub-title {
    color: #9ed6c3;
    font-size: 1rem;
    margin-bottom: 0.8rem;
    letter-spacing: 0.4px;
}

.neon-line {
    height: 3px;
    border-radius: 999px;
    background: linear-gradient(90deg, #00ffae, #00d9ff, #00ffae);
    box-shadow: 0 0 14px rgba(0,255,174,0.45);
    margin-bottom: 1rem;
}

.badge-row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 1rem;
}

.badge {
    padding: 7px 12px;
    border-radius: 999px;
    background: rgba(0,255,174,0.07);
    border: 1px solid rgba(0,255,174,0.20);
    color: #caffee;
    font-size: 12px;
}

.glass-panel {
    background: linear-gradient(180deg, rgba(6,14,26,0.94), rgba(8,18,36,0.94));
    border: 1px solid rgba(0,255,174,0.15);
    border-radius: 20px;
    padding: 16px;
    box-shadow:
        0 0 20px rgba(0,255,174,0.06),
        inset 0 0 25px rgba(0,217,255,0.02);
    margin-bottom: 1rem;
}

.metric-box {
    background: linear-gradient(180deg, rgba(7,15,27,0.98), rgba(8,22,40,0.96));
    border: 1px solid rgba(0,255,174,0.18);
    border-radius: 18px;
    padding: 18px 14px;
    text-align: center;
    box-shadow:
        0 0 15px rgba(0,255,174,0.08),
        inset 0 0 16px rgba(0,255,174,0.03);
}

.metric-label {
    color: #8fb6a8;
    font-size: 13px;
    letter-spacing: 1px;
    margin-bottom: 8px;
}

.metric-value {
    color: #00ffae;
    font-size: 1.8rem;
    font-weight: 900;
    text-shadow: 0 0 12px rgba(0,255,174,0.25);
}

.section-title {
    color: #00e7ff;
    font-size: 1.08rem;
    font-weight: 800;
    margin: 0.6rem 0 0.9rem 0;
    letter-spacing: 1px;
    text-shadow: 0 0 10px rgba(0,231,255,0.16);
}

.small-note {
    color: #7f96a1;
    font-size: 12px;
    letter-spacing: 0.4px;
}

.terminal-box {
    background: #02070f;
    color: #00ffae;
    border: 1px solid rgba(0,255,174,0.18);
    border-radius: 16px;
    padding: 14px;
    min-height: 230px;
    box-shadow: inset 0 0 20px rgba(0,255,174,0.04);
    font-size: 13px;
    line-height: 1.6;
}

.mode-card {
    background: linear-gradient(180deg, rgba(7,15,27,0.98), rgba(8,22,40,0.96));
    border: 1px solid rgba(0,255,174,0.14);
    border-radius: 18px;
    padding: 14px;
    margin-bottom: 10px;
}

.mode-label {
    color: #00ffae;
    font-weight: 800;
    margin-bottom: 6px;
}

.attack-chip {
    display: inline-block;
    margin-right: 8px;
    margin-top: 6px;
    padding: 5px 10px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 700;
    border: 1px solid rgba(0,255,174,0.18);
    background: rgba(0,255,174,0.06);
    color: #ccfff0;
}

.stTextInput > div > div > input,
.stNumberInput input,
.stSelectbox div[data-baseweb="select"] > div,
.stMultiSelect div[data-baseweb="select"] > div,
textarea {
    background: #091321 !important;
    color: #eafff7 !important;
    border: 1px solid rgba(0,255,174,0.18) !important;
    border-radius: 14px !important;
}

.stButton > button {
    background: linear-gradient(90deg, #00ffae, #00d9ff);
    color: #02110c !important;
    font-weight: 900;
    border: none;
    border-radius: 14px;
    padding: 0.75rem 1.4rem;
    box-shadow:
        0 0 18px rgba(0,255,174,0.22),
        0 0 28px rgba(0,217,255,0.10);
}

.stButton > button:hover {
    transform: translateY(-1px) scale(1.01);
}

.stProgress > div > div > div > div {
    background: linear-gradient(90deg, #00ffae, #00d9ff) !important;
}

div[data-testid="stDataFrame"] {
    border: 1px solid rgba(0,255,174,0.12);
    border-radius: 16px;
    overflow: hidden;
}

div[data-testid="stMetric"] {
    background: linear-gradient(180deg, rgba(7,15,27,0.98), rgba(8,22,40,0.96));
    padding: 10px;
    border-radius: 16px;
    border: 1px solid rgba(0,255,174,0.14);
}

::-webkit-scrollbar {
    width: 10px;
    height: 10px;
}
::-webkit-scrollbar-track {
    background: #07101b;
}
::-webkit-scrollbar-thumb {
    background: linear-gradient(180deg, #00ffae, #00d9ff);
    border-radius: 999px;
}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="main-title">LOW9INE ELITE SCANNER</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-title">Network Exposure • Offline Threat Intelligence • Live Recon Dashboard</div>',
    unsafe_allow_html=True
)
st.markdown('<div class="neon-line"></div>', unsafe_allow_html=True)

st.markdown("""
<div class="badge-row">
    <div class="badge">LIVE PORT SCAN RESULTS</div>
    <div class="badge">TCP CONNECT</div>
    <div class="badge">UDP PROBE</div>
    <div class="badge">PRESET SCAN MODES</div>
    <div class="badge">CVE / CVSS / MITRE</div>
    <div class="badge">CSV / JSON / HTML EXPORT</div>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div class="glass-panel">
    <div style="color:#00ffae; font-weight:800; margin-bottom:8px;">SYSTEM STATUS</div>
    <div style="color:#9ed6c3; line-height:1.7;">
        [ OK ] UI core loaded<br>
        [ OK ] Scan engine initialized<br>
        [ OK ] Offline threat intelligence ready<br>
        [ OK ] Scan mode presets loaded<br>
        [ OK ] MITRE ATT&CK mapping ready<br>
        [ OK ] Live terminal output active
    </div>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("## ⚙️ Scan Configuration")
    mode_group = st.selectbox("Mode Category", list(SCAN_MODE_GROUPS.keys()))
    mode_name = st.selectbox("Scan Mode", list(SCAN_MODE_GROUPS[mode_group].keys()))
    selected_mode = SCAN_MODE_GROUPS[mode_group][mode_name]

    target = st.text_input("Target IP / Domain", placeholder="example.com")
    scan_engine = st.selectbox("Scan Engine", list(SCAN_FUNCTIONS.keys()))
    st.caption(SCAN_DESC.get(scan_engine, ""))

    timeout = st.number_input("Timeout", min_value=0.5, max_value=10.0, value=1.0, step=0.5)
    threads = st.slider("Threads", 10, 300, 100, 10)

    ports_input = st.text_input(
        "Ports",
        value=selected_mode["ports"] if selected_mode["ports"] else "20-100"
    )

    st.markdown(f"""
    <div class="mode-card">
        <div class="mode-label">{mode_name}</div>
        <div style="color:#9ed6c3; font-size:13px;">{selected_mode["description"]}</div>
        <div class="attack-chip">{selected_mode["simulation"]}</div>
        <div class="attack-chip">{selected_mode["focus"]}</div>
    </div>
    """, unsafe_allow_html=True)

    start_scan = st.button("🚀 START ELITE SCAN")

def run_single_scan(target_ip, port, scan_type, timeout):
    scan_func = SCAN_FUNCTIONS[scan_type]
    return scan_func(target_ip, port, timeout, requested_scan=scan_type)

if start_scan:
    st.session_state.live_logs = []

    if not validate_target(target):
        st.error("Invalid target.")
        st.stop()

    target_ip = resolve_target(target)
    if not target_ip:
        st.error("Could not resolve target.")
        st.stop()

    try:
        ports = parse_ports(ports_input)
        if not ports:
            st.error("No valid ports found.")
            st.stop()
    except Exception:
        st.error("Invalid port format. Example: 22,80,443 or 1-1024")
        st.stop()

    discovery = is_host_reachable_tcp(target_ip, timeout=1.0)

    st.markdown('<div class="section-title">TARGET INTELLIGENCE</div>', unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(
            f'<div class="metric-box"><div class="metric-label">TARGET</div><div class="metric-value" style="font-size:1.45rem;">{target_ip}</div></div>',
            unsafe_allow_html=True
        )
    with c2:
        st.markdown(
            f'<div class="metric-box"><div class="metric-label">REACHABLE</div><div class="metric-value">{"YES" if discovery["reachable"] else "NO"}</div></div>',
            unsafe_allow_html=True
        )
    with c3:
        st.markdown(
            f'<div class="metric-box"><div class="metric-label">DISCOVERY</div><div class="metric-value" style="font-size:1.25rem;">{discovery["method"]}</div></div>',
            unsafe_allow_html=True
        )
    with c4:
        st.markdown(
            f'<div class="metric-box"><div class="metric-label">ENGINE</div><div class="metric-value" style="font-size:1.05rem;">{scan_engine}</div></div>',
            unsafe_allow_html=True
        )

    st.markdown('<div class="section-title">LIVE OPERATION</div>', unsafe_allow_html=True)
    left_col, right_col = st.columns([1.55, 1])

    live_table = left_col.empty()
    terminal_box = right_col.empty()
    progress_bar = st.progress(0)

    results = []
    start_time = time.time()

    boot_lines = [
        f"[INIT] Resolving target {target}",
        f"[INIT] Target IP => {target_ip}",
        f"[INIT] Selected mode => {mode_name}",
        f"[INIT] Selected engine => {scan_engine}",
        f"[INIT] Engine description => {SCAN_DESC.get(scan_engine, '')}",
        f"[INIT] Simulation label => {selected_mode['simulation']}",
        f"[INIT] Focus => {selected_mode['focus']}",
        f"[INIT] Total ports => {len(ports)}",
        "[INIT] Threat enrichment => CVE / CVSS / MITRE active",
        "[INIT] Starting live enumeration..."
    ]
    st.session_state.live_logs.extend(boot_lines)

    terminal_box.markdown(
        '<div class="terminal-box">' + "<br>".join(st.session_state.live_logs[-18:]) + '</div>',
        unsafe_allow_html=True
    )

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {
            executor.submit(run_single_scan, target_ip, port, scan_engine, timeout): port
            for port in ports
        }

        for i, future in enumerate(as_completed(future_map)):
            result = future.result()
            results.append(result)

            log_line = (
                f"[{result['State']}] "
                f"Port {result['Port']}/{result['Protocol']} "
                f"=> {result['Service']} | Risk={result['Risk']} | CVSS={result['CVSS']}"
            )
            st.session_state.live_logs.append(log_line)

            temp_df = pd.DataFrame(results).sort_values("Port")
            live_table.dataframe(temp_df, width="stretch")

            terminal_box.markdown(
                '<div class="terminal-box">' + "<br>".join(st.session_state.live_logs[-18:]) + '</div>',
                unsafe_allow_html=True
            )

            progress_bar.progress((i + 1) / len(ports))

    duration = round(time.time() - start_time, 2)
    df = pd.DataFrame(results).sort_values("Port").reset_index(drop=True)

    interesting_states = {"Open", "Responsive", "Open|Filtered", "Unfiltered", "Open (Window)"}
    open_df = df[df["State"].isin(interesting_states)].copy()
    critical_df = df[df["Risk"].isin(["Critical", "High"])].copy()

    st.markdown('<div class="section-title">SCAN SUMMARY</div>', unsafe_allow_html=True)
    s1, s2, s3, s4, s5 = st.columns(5)
    with s1:
        st.metric("Total Ports", len(df))
    with s2:
        st.metric("Open / Interesting", len(open_df))
    with s3:
        st.metric("Closed", len(df[df["State"] == "Closed"]))
    with s4:
        st.metric("High / Critical", len(critical_df))
    with s5:
        st.metric("Duration", f"{duration}s")

    summary_text = summarize_findings(df)

    st.markdown('<div class="section-title">OPERATION SUMMARY</div>', unsafe_allow_html=True)
    st.markdown(f"""
    <div class="glass-panel">
        <div style="color:#9ed6c3; line-height:1.7;">{summary_text}</div>
        <div class="attack-chip">{selected_mode["simulation"]}</div>
        <div class="attack-chip">{selected_mode["focus"]}</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="section-title">FULL RESULTS</div>', unsafe_allow_html=True)
    st.dataframe(df, width="stretch")

    st.markdown('<div class="section-title">PRIORITY FINDINGS</div>', unsafe_allow_html=True)
    if not critical_df.empty:
        st.dataframe(critical_df, width="stretch")
    else:
        st.info("No High or Critical findings in this run.")

    st.markdown('<div class="section-title">VISUALIZATION</div>', unsafe_allow_html=True)
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        state_df = df["State"].value_counts().reset_index()
        state_df.columns = ["State", "Count"]
        fig_state = px.pie(
            state_df,
            names="State",
            values="Count",
            title="State Distribution",
            hole=0.45
        )
        fig_state.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#d7ffe8"
        )
        st.plotly_chart(fig_state)

    with chart_col2:
        risk_df = df["Risk"].value_counts().reset_index()
        risk_df.columns = ["Risk", "Count"]
        fig_risk = px.bar(
            risk_df,
            x="Risk",
            y="Count",
            title="Risk Distribution",
            text_auto=True
        )
        fig_risk.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#d7ffe8"
        )
        st.plotly_chart(fig_risk)

    st.markdown('<div class="section-title">VULNERABILITY INTELLIGENCE</div>', unsafe_allow_html=True)
    displayed = False
    for _, row in open_df.iterrows():
        if row["Threats"]:
            displayed = True
            threat_lines = "<br>".join([f"- {item}" for item in row["Threats"]])
            mitre_lines = "<br>".join([f"- {item}" for item in row["MITRE"]]) if row["MITRE"] else "- None"
            st.markdown(f"""
            <div class="glass-panel">
                <div style="color:#00ffae; font-weight:800; margin-bottom:6px;">
                    Port {row["Port"]}/{row["Protocol"]} • {row["Service"]} • Risk {row["Risk"]} • CVSS {row["CVSS"]}
                </div>
                <div style="color:#9ed6c3; margin-bottom:8px;">{row["Banner"] if row["Banner"] else "No banner captured"}</div>
                <div style="color:#d7ffe8; margin-bottom:8px;"><strong>Threats:</strong><br>{threat_lines}</div>
                <div style="color:#d7ffe8;"><strong>MITRE Mapping:</strong><br>{mitre_lines}</div>
                <div class="attack-chip">{row["Simulation"]}</div>
                <div class="attack-chip">{row["Focus"]}</div>
            </div>
            """, unsafe_allow_html=True)
    if not displayed:
        st.info("No threat-enriched open services were found in this run.")

    st.markdown('<div class="section-title">EXPORT REPORTS</div>', unsafe_allow_html=True)
    csv_bytes = df.to_csv(index=False).encode("utf-8")
    json_bytes = generate_json_report(results).encode("utf-8")
    html_bytes = generate_html_report(df, target, target_ip, mode_name, scan_engine, duration).encode("utf-8")

    d1, d2, d3 = st.columns(3)
    with d1:
        st.download_button("Download CSV", csv_bytes, "low9ine_report.csv", "text/csv")
    with d2:
        st.download_button("Download JSON", json_bytes, "low9ine_report.json", "application/json")
    with d3:
        st.download_button("Download HTML", html_bytes, "low9ine_report.html", "text/html")

    st.session_state.scan_history.append({
        "target": target,
        "resolved_ip": target_ip,
        "mode": mode_name,
        "engine": scan_engine,
        "ports": ports_input,
        "duration": duration,
        "findings": len(open_df),
        "high_critical": len(critical_df),
    })

if st.session_state.scan_history:
    st.markdown('<div class="section-title">SCAN HISTORY</div>', unsafe_allow_html=True)
    history_df = pd.DataFrame(st.session_state.scan_history)
    st.dataframe(history_df, width="stretch")

st.markdown(
    '<div class="small-note">LOW9INE ELITE SCANNER • Authorized network auditing only • Offline enrichment database enabled</div>',
    unsafe_allow_html=True
)