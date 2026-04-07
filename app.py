import time
import pandas as pd
import streamlit as st
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.basic_scans import tcp_connect_scan, udp_scan
from scanner.raw_scans import raw_scan_not_available
from utils.helpers import (
    resolve_target,
    validate_target,
    parse_ports,
)
from utils.exporter import generate_html_report


st.set_page_config(
    page_title="LOW9INE ELITE PORT SCANNER",
    page_icon="💀",
    layout="wide"
)

st.markdown("""
<style>
html, body, [class*="css"] {
    background: #05070d;
    color: #d7ffe8;
    font-family: Consolas, monospace;
}
.stApp {
    background:
        radial-gradient(circle at top left, rgba(0,255,170,0.08), transparent 25%),
        radial-gradient(circle at top right, rgba(0,200,255,0.08), transparent 25%),
        linear-gradient(180deg, #05070d 0%, #08111f 100%);
}
.block-container {
    padding-top: 1rem;
    padding-bottom: 2rem;
    max-width: 1400px;
}
.main-title {
    font-size: 2.4rem;
    font-weight: 900;
    color: #00ffae;
    text-shadow: 0 0 10px rgba(0,255,174,0.28);
    margin-bottom: 0.2rem;
}
.sub-title {
    color: #8cb8a8;
    font-size: 0.95rem;
    margin-bottom: 1rem;
}
.panel {
    background: rgba(10, 16, 28, 0.9);
    border: 1px solid rgba(0,255,174,0.15);
    border-radius: 18px;
    padding: 18px;
    box-shadow: 0 0 18px rgba(0,255,174,0.06);
    margin-bottom: 16px;
}
.metric-box {
    background: linear-gradient(180deg, rgba(10,16,28,0.95), rgba(8,18,36,0.95));
    border: 1px solid rgba(0,255,174,0.18);
    border-radius: 16px;
    padding: 14px;
    text-align: center;
    box-shadow: 0 0 14px rgba(0,255,174,0.08);
}
.metric-label {
    color: #9ab6aa;
    font-size: 13px;
    margin-bottom: 6px;
}
.metric-value {
    color: #00ffae;
    font-size: 28px;
    font-weight: 800;
}
.section-title {
    color: #00e7ff;
    font-size: 1.1rem;
    font-weight: 800;
    margin: 6px 0 12px 0;
}
.badge {
    display: inline-block;
    padding: 6px 10px;
    border-radius: 999px;
    background: rgba(0,255,174,0.08);
    border: 1px solid rgba(0,255,174,0.18);
    color: #bfffe4;
    font-size: 12px;
    margin-right: 8px;
    margin-bottom: 8px;
}
.stTextInput > div > div > input,
.stNumberInput input,
.stSelectbox div[data-baseweb="select"] > div,
textarea {
    background-color: #0a1220 !important;
    color: #eafff7 !important;
    border: 1px solid rgba(0,255,174,0.2) !important;
    border-radius: 12px !important;
}
.stButton > button {
    background: linear-gradient(90deg, #00ffae, #00d9ff);
    color: #000 !important;
    font-weight: 800;
    border: none;
    border-radius: 14px;
    padding: 0.7rem 1.6rem;
    box-shadow: 0 0 18px rgba(0,255,174,0.2);
}
.stButton > button:hover {
    transform: scale(1.02);
    transition: 0.2s ease;
}
.small-note {
    color: #8da2ad;
    font-size: 12px;
}
</style>
""", unsafe_allow_html=True)


SCAN_FUNCTIONS = {
    "TCP Connect": tcp_connect_scan,
    "UDP Probe": udp_scan,
    "SYN Scan": raw_scan_not_available,
    "ACK Scan": raw_scan_not_available,
    "NULL Scan": raw_scan_not_available,
    "XMAS Scan": raw_scan_not_available,
    "Window Scan": raw_scan_not_available,
    "Maimon Scan": raw_scan_not_available,
}


def run_single_scan(target_ip, port, scan_type, timeout):
    scan_func = SCAN_FUNCTIONS.get(scan_type)
    return scan_func(target_ip, port, timeout, requested_scan=scan_type)


st.markdown('<div class="main-title">💀 LOW9INE ELITE PORT SCANNER</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-title">Professional modular network auditing dashboard for authorized asset visibility</div>',
    unsafe_allow_html=True
)

st.markdown("""
<div class="panel">
    <span class="badge">Modular Structure</span>
    <span class="badge">TCP Connect</span>
    <span class="badge">UDP Probe</span>
    <span class="badge">Banner Grabbing</span>
    <span class="badge">CSV Export</span>
    <span class="badge">HTML Report</span>
</div>
""", unsafe_allow_html=True)

st.markdown('<div class="section-title">TARGET CONFIGURATION</div>', unsafe_allow_html=True)

col1, col2, col3 = st.columns(3)
with col1:
    target = st.text_input("Target IP / Domain", placeholder="example.com or 192.168.1.1")
with col2:
    ports_input = st.text_input("Ports", value="20-100")
with col3:
    timeout = st.number_input("Timeout (seconds)", min_value=0.5, max_value=10.0, value=1.0, step=0.5)

col4, col5 = st.columns(2)
with col4:
    scan_type = st.selectbox("Scan Type", list(SCAN_FUNCTIONS.keys()))
with col5:
    threads = st.slider("Threads", min_value=10, max_value=300, value=100, step=10)

if st.button("🚀 START SCAN"):
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
        st.error("Invalid port format. Use: 22,80,443 or 1-1000")
        st.stop()

    st.success(f"Target resolved: {target} → {target_ip}")

    start_time = time.time()
    progress_bar = st.progress(0)
    live_table = st.empty()

    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {
            executor.submit(run_single_scan, target_ip, port, scan_type, timeout): port
            for port in ports
        }

        completed = 0
        for future in as_completed(future_map):
            result = future.result()
            results.append(result)
            completed += 1
            progress_bar.progress(completed / len(ports))

            temp_df = pd.DataFrame(results).sort_values(by="Port")
            live_table.dataframe(temp_df, width="stretch")

    duration = round(time.time() - start_time, 2)
    df = pd.DataFrame(results).sort_values(by="Port").reset_index(drop=True)

    interesting_states = {"Open", "Open|Filtered", "Responsive"}
    open_count = len(df[df["State"].isin(interesting_states)])
    closed_count = len(df[df["State"] == "Closed"])
    filtered_count = len(df[df["State"].isin(["Filtered", "Unavailable", "Unknown", "Error"])])

    st.markdown('<div class="section-title">SCAN SUMMARY</div>', unsafe_allow_html=True)
    m1, m2, m3, m4 = st.columns(4)

    with m1:
        st.markdown(f"""
        <div class="metric-box">
            <div class="metric-label">TARGET</div>
            <div class="metric-value" style="font-size:20px;">{target_ip}</div>
        </div>
        """, unsafe_allow_html=True)

    with m2:
        st.markdown(f"""
        <div class="metric-box">
            <div class="metric-label">OPEN / INTERESTING</div>
            <div class="metric-value">{open_count}</div>
        </div>
        """, unsafe_allow_html=True)

    with m3:
        st.markdown(f"""
        <div class="metric-box">
            <div class="metric-label">CLOSED</div>
            <div class="metric-value">{closed_count}</div>
        </div>
        """, unsafe_allow_html=True)

    with m4:
        st.markdown(f"""
        <div class="metric-box">
            <div class="metric-label">FILTERED / OTHER</div>
            <div class="metric-value">{filtered_count}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown('<div class="section-title">FULL RESULTS</div>', unsafe_allow_html=True)
    st.dataframe(df, width="stretch")

    interesting_df = df[df["State"].isin(interesting_states)].copy()
    st.markdown('<div class="section-title">OPEN / INTERESTING PORTS</div>', unsafe_allow_html=True)

    if not interesting_df.empty:
        def highlight_rows(row):
            if row["Risk"] == "High":
                return ["background-color: rgba(255, 0, 0, 0.20)"] * len(row)
            elif row["Risk"] == "Medium":
                return ["background-color: rgba(255, 165, 0, 0.18)"] * len(row)
            return ["background-color: rgba(0, 255, 174, 0.10)"] * len(row)

        st.dataframe(interesting_df.style.apply(highlight_rows, axis=1), width="stretch")
    else:
        st.warning("No open or interesting ports found.")

    csv_bytes = df.to_csv(index=False).encode("utf-8")
    html_report = generate_html_report(df, target, target_ip, scan_type, duration)

    st.markdown('<div class="section-title">EXPORT REPORTS</div>', unsafe_allow_html=True)

    c1, c2 = st.columns(2)
    with c1:
        st.download_button(
            label="Download CSV Report",
            data=csv_bytes,
            file_name=f"low9ine_scan_{target_ip}_{scan_type.replace(' ', '_').lower()}.csv",
            mime="text/csv"
        )
    with c2:
        st.download_button(
            label="Download HTML Report",
            data=html_report.encode("utf-8"),
            file_name=f"low9ine_scan_{target_ip}_{scan_type.replace(' ', '_').lower()}.html",
            mime="text/html"
        )

    st.success(f"Scan completed in {duration} seconds.")

st.markdown(
    '<div class="small-note">LOW9INE ELITE PORT SCANNER • Use only on systems you own or are explicitly authorized to assess</div>',
    unsafe_allow_html=True
)