import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import TypedDict

import pandas as pd
import plotly.express as px
import streamlit as st

try:
    import feedparser
except ImportError:
    feedparser = None

from utils.report import generate_report


class ScanResult(TypedDict):
    port: int
    status: str
    service: str
    banner: str
    risk: str


st.set_page_config(
    page_title="Low9ine Elite Port Scanner",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
    .stApp {
        background: linear-gradient(135deg, #050814, #0a1020, #11182b);
        color: #e6e6e6;
    }

    h1, h2, h3, h4 {
        color: #00ffcc !important;
    }

    .main-title {
        font-size: 40px;
        font-weight: 800;
        color: #00ffcc;
        text-shadow: 0 0 10px rgba(0,255,204,0.35);
        margin-bottom: 0.2rem;
    }

    .sub-text {
        color: #9fb3d9;
        font-size: 15px;
        margin-bottom: 1rem;
    }

    .info-box {
        background: rgba(15, 26, 48, 0.95);
        border: 1px solid #21406d;
        border-radius: 14px;
        padding: 14px;
        color: #a9d0ff;
        margin-bottom: 14px;
    }

    .success-box {
        background: rgba(10, 39, 26, 0.95);
        border: 1px solid #1f6a44;
        border-radius: 14px;
        padding: 14px;
        color: #88ffba;
        margin-bottom: 14px;
    }

    .danger-box {
        background: rgba(45, 16, 16, 0.95);
        border: 1px solid #7c2b2b;
        border-radius: 14px;
        padding: 14px;
        color: #ff9c9c;
        margin-bottom: 14px;
    }

    .warning-box {
        background: rgba(45, 35, 10, 0.95);
        border: 1px solid #8f6a16;
        border-radius: 14px;
        padding: 14px;
        color: #ffd66d;
        margin-bottom: 14px;
    }

    .metric-card {
        background: linear-gradient(180deg, #10192d, #131f38);
        border: 1px solid #263b63;
        border-radius: 18px;
        padding: 18px;
        text-align: center;
        box-shadow: 0 0 18px rgba(0,255,204,0.07);
    }

    .metric-card h3 {
        font-size: 28px;
        margin: 0;
        color: #ffffff !important;
    }

    .metric-card p {
        margin: 6px 0 0 0;
        color: #9ab3d3;
        font-size: 14px;
    }

    .panel {
        background: rgba(11, 18, 34, 0.95);
        border: 1px solid #22365c;
        border-radius: 18px;
        padding: 16px;
        margin-bottom: 18px;
        box-shadow: 0 0 20px rgba(0, 255, 204, 0.05);
    }

    .terminal-box {
        background: #02060f;
        color: #6dff8b;
        border: 1px solid #134d2f;
        border-radius: 14px;
        padding: 12px;
        font-family: Consolas, monospace;
        font-size: 13px;
        height: 320px;
        overflow-y: auto;
        white-space: pre-wrap;
    }

    .news-item {
        padding: 10px 0;
        border-bottom: 1px solid #1d2d4d;
    }

    .news-item:last-child {
        border-bottom: none;
    }

    .small-label {
        color: #8ea8cf;
        font-size: 13px;
    }
</style>
""", unsafe_allow_html=True)

COMMON_PORTS: dict[int, str] = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    162: "SNMPTRAP",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

HIGH_RISK_PORTS: set[int] = {
    21, 23, 25, 53, 69, 111, 135, 137, 138, 139,
    161, 445, 1433, 3306, 3389, 5432, 5900, 6379
}

RSS_FEEDS: list[str] = [
    "https://thehackernews.com/feeds/posts/default",
    "https://www.darkreading.com/rss.xml",
    "https://www.helpnetsecurity.com/feed/"
]


def resolve_target(target: str) -> str | None:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def detect_service(port: int) -> str:
    return COMMON_PORTS.get(port, "Unknown")


def get_risk_level(port: int, status: str) -> str:
    if status != "Open":
        return "Low"
    if port in HIGH_RISK_PORTS:
        return "High"
    if port in {22, 80, 443, 8080, 8443}:
        return "Medium"
    return "Low"


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))

            if port in {80, 8080, 8000, 8888}:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")

            banner = sock.recv(1024).decode(errors="ignore").strip()
            return banner[:150] if banner else "No banner"
    except Exception:
        return "No banner"


def scan_single_port(ip: str, port: int, timeout: float, enable_banner: bool) -> ScanResult:
    result: ScanResult = {
        "port": port,
        "status": "Closed",
        "service": detect_service(port),
        "banner": "N/A",
        "risk": "Low"
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            response = sock.connect_ex((ip, port))

            if response == 0:
                result["status"] = "Open"
                result["risk"] = get_risk_level(port, "Open")
                if enable_banner:
                    result["banner"] = grab_banner(ip, port, timeout)
            else:
                result["status"] = "Closed"
                result["risk"] = "Low"
    except Exception:
        result["status"] = "Filtered"
        result["risk"] = "Low"

    return result


def scan_ports(
    ip: str,
    start_port: int,
    end_port: int,
    timeout: float,
    max_threads: int,
    enable_banner: bool,
    progress_bar,
    status_placeholder,
    log_placeholder
) -> tuple[list[ScanResult], list[str]]:
    ports = list(range(start_port, end_port + 1))
    total_ports = len(ports)
    results: list[ScanResult] = []
    live_logs: list[str] = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(scan_single_port, ip, port, timeout, enable_banner): port
            for port in ports
        }

        completed = 0
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            completed += 1

            progress_bar.progress(completed / total_ports)
            status_placeholder.info(f"Scanning... {completed}/{total_ports} ports completed")

            log_line = (
                f"[{datetime.now().strftime('%H:%M:%S')}] "
                f"PORT {result['port']} | STATUS={result['status']} | "
                f"SERVICE={result['service']} | RISK={result['risk']}"
            )
            live_logs.append(log_line)

            if len(live_logs) > 80:
                live_logs = live_logs[-80:]

            log_placeholder.markdown(
                f"<div class='terminal-box'>{'<br>'.join(live_logs)}</div>",
                unsafe_allow_html=True
            )

    results.sort(key=lambda item: item["port"])
    return results, live_logs


def to_csv_bytes(df: pd.DataFrame) -> bytes:
    return df.to_csv(index=False).encode("utf-8")


def read_file_bytes(path: str) -> bytes:
    with open(path, "rb") as file:
        return file.read()


@st.cache_data(ttl=1800)
def load_cyber_news() -> list[dict[str, str]]:
    if feedparser is None:
        return []

    items: list[dict[str, str]] = []

    for feed_url in RSS_FEEDS:
        try:
            feed = feedparser.parse(feed_url)
            for entry in feed.entries[:4]:
                items.append({
                    "title": entry.get("title", "No title"),
                    "link": entry.get("link", "#"),
                    "source": feed.feed.get("title", "Cyber Feed")
                })
        except Exception:
            continue

    return items[:8]


def get_host_info(target: str, ip: str) -> dict[str, str]:
    hostname = "Unknown"
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    return {
        "Target": target,
        "Resolved IP": ip,
        "Hostname": hostname,
        "Scan Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


if "results_df" not in st.session_state:
    st.session_state.results_df = None

if "results_raw" not in st.session_state:
    st.session_state.results_raw = None

if "report_path" not in st.session_state:
    st.session_state.report_path = None

if "host_info" not in st.session_state:
    st.session_state.host_info = None

if "selected_filter" not in st.session_state:
    st.session_state.selected_filter = "All"

st.sidebar.title("⚙️ Low9ine Controls")

target = st.sidebar.text_input("Target IP / Domain", value="scanme.nmap.org")

scan_type = st.sidebar.selectbox(
    "Scan Type",
    ["TCP Connect Scan", "Banner Scan", "Fast Scan"]
)

start_port = st.sidebar.number_input("Start Port", min_value=1, max_value=65535, value=1)
end_port = st.sidebar.number_input("End Port", min_value=1, max_value=65535, value=1024)
timeout = st.sidebar.slider("Timeout (seconds)", 0.1, 3.0, 0.5, 0.1)
max_threads = st.sidebar.slider("Threads", 10, 500, 100, 10)
show_news = st.sidebar.checkbox("Show Cyber News Panel", value=True)

if scan_type == "TCP Connect Scan":
    banner_enabled = False
elif scan_type == "Banner Scan":
    banner_enabled = True
else:
    banner_enabled = False
    max_threads = 300
    timeout = 0.3

scan_btn = st.sidebar.button("🚀 Start Scan", width="stretch")

st.markdown("<div class='main-title'>🛡️ LOW9INE ELITE PORT SCANNER</div>", unsafe_allow_html=True)
st.markdown(
    "<div class='sub-text'>Advanced dashboard with scan modes, live log, analytics, host intelligence, and export features.</div>",
    unsafe_allow_html=True
)
st.markdown(
    f"""
    <div class="info-box">
        <b>Active Scan Mode:</b> {scan_type}
    </div>
    """,
    unsafe_allow_html=True
)

if scan_btn:
    if start_port > end_port:
        st.error("Start Port cannot be greater than End Port.")
        st.stop()

    ip = resolve_target(target)
    if not ip:
        st.error("Could not resolve target. Please enter a valid IP or domain.")
        st.stop()

    st.session_state.host_info = get_host_info(target, ip)

    st.markdown(
        f"""
        <div class="success-box">
            Target resolved successfully: <b>{target}</b> → <b>{ip}</b>
        </div>
        """,
        unsafe_allow_html=True
    )

    top_left, top_right = st.columns([2, 1])

    with top_left:
        progress_bar = st.progress(0)
        status_placeholder = st.empty()

    with top_right:
        st.markdown("<div class='panel'><h4>💻 Live Terminal Log</h4></div>", unsafe_allow_html=True)
        log_placeholder = st.empty()

    with st.spinner("Scanning ports..."):
        results, _live_logs = scan_ports(
            ip=ip,
            start_port=int(start_port),
            end_port=int(end_port),
            timeout=float(timeout),
            max_threads=int(max_threads),
            enable_banner=banner_enabled,
            progress_bar=progress_bar,
            status_placeholder=status_placeholder,
            log_placeholder=log_placeholder
        )

    status_placeholder.success("Scan completed successfully.")

    df = pd.DataFrame(results)
    st.session_state.results_df = df
    st.session_state.results_raw = results
    st.session_state.report_path = generate_report(results)
    st.session_state.selected_filter = "All"

if st.session_state.results_df is not None:
    df = st.session_state.results_df.copy()

    total_ports = len(df)
    open_count = int((df["status"] == "Open").sum())
    closed_count = int((df["status"] == "Closed").sum())
    filtered_count = int((df["status"] == "Filtered").sum())

    high_risk_df = df[(df["status"] == "Open") & (df["risk"] == "High")].copy()

    host_col, news_col = st.columns([1, 1])

    with host_col:
        st.markdown("<div class='panel'><h3>🖥️ Host Information</h3></div>", unsafe_allow_html=True)
        if st.session_state.host_info:
            info = st.session_state.host_info
            st.markdown(
                f"""
                <div class="info-box">
                    <b>Target:</b> {info['Target']}<br>
                    <b>Resolved IP:</b> {info['Resolved IP']}<br>
                    <b>Hostname:</b> {info['Hostname']}<br>
                    <b>Scan Time:</b> {info['Scan Time']}
                </div>
                """,
                unsafe_allow_html=True
            )

    with news_col:
        if show_news:
            st.markdown("<div class='panel'><h3>📰 Cybersecurity News</h3></div>", unsafe_allow_html=True)
            news_items = load_cyber_news()
            if feedparser is None:
                st.warning("feedparser is not installed. News panel is disabled.")
            elif news_items:
                for item in news_items:
                    st.markdown(
                        f"""
                        <div class="news-item">
                            <a href="{item['link']}" target="_blank" style="color:#8fd3ff; text-decoration:none; font-weight:600;">
                                {item['title']}
                            </a><br>
                            <span class="small-label">{item['source']}</span>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
            else:
                st.info("Unable to load cyber news right now.")

    c1, c2, c3, c4, c5 = st.columns(5)

    with c1:
        st.markdown(f"<div class='metric-card'><h3>{total_ports}</h3><p>Total Ports</p></div>", unsafe_allow_html=True)
    with c2:
        st.markdown(f"<div class='metric-card'><h3>{open_count}</h3><p>Open</p></div>", unsafe_allow_html=True)
    with c3:
        st.markdown(f"<div class='metric-card'><h3>{closed_count}</h3><p>Closed</p></div>", unsafe_allow_html=True)
    with c4:
        st.markdown(f"<div class='metric-card'><h3>{filtered_count}</h3><p>Filtered</p></div>", unsafe_allow_html=True)
    with c5:
        st.markdown(f"<div class='metric-card'><h3>{len(high_risk_df)}</h3><p>High Risk</p></div>", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    if not high_risk_df.empty:
        st.markdown(
            """
            <div class="danger-box">
                High-risk open ports detected. Review exposed services immediately.
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            """
            <div class="success-box">
                No high-risk open ports detected in the scanned range.
            </div>
            """,
            unsafe_allow_html=True
        )

    st.subheader("🎯 Result Filters")

    f1, f2, f3, f4 = st.columns(4)

    with f1:
        if st.button("All Results", width="stretch"):
            st.session_state.selected_filter = "All"
    with f2:
        if st.button("Open Ports", width="stretch"):
            st.session_state.selected_filter = "Open"
    with f3:
        if st.button("Closed Ports", width="stretch"):
            st.session_state.selected_filter = "Closed"
    with f4:
        if st.button("Filtered Ports", width="stretch"):
            st.session_state.selected_filter = "Filtered"

    selected_filter = st.session_state.selected_filter

    if selected_filter == "Open":
        display_df = df[df["status"] == "Open"].copy()
    elif selected_filter == "Closed":
        display_df = df[df["status"] == "Closed"].copy()
    elif selected_filter == "Filtered":
        display_df = df[df["status"] == "Filtered"].copy()
    else:
        display_df = df.copy()

    st.markdown(
        f"""
        <div class="info-box">
            <b>Current Filter:</b> {selected_filter}
        </div>
        """,
        unsafe_allow_html=True
    )

    left_col, right_col = st.columns([2, 1])

    with left_col:
        st.markdown("<div class='panel'><h3>📋 Scan Results Table</h3></div>", unsafe_allow_html=True)
        st.dataframe(display_df, width="stretch", height=450)

    with right_col:
        st.markdown("<div class='panel'><h3>📊 Port Distribution</h3></div>", unsafe_allow_html=True)
        chart_df = pd.DataFrame({
            "Status": ["Open", "Closed", "Filtered"],
            "Count": [open_count, closed_count, filtered_count]
        })
        fig = px.pie(chart_df, names="Status", values="Count", title="Scan Summary")
        st.plotly_chart(fig, width="stretch")

    t1, t2 = st.columns(2)

    with t1:
        st.markdown("<div class='panel'><h3>🔓 Open Ports</h3></div>", unsafe_allow_html=True)
        if open_count == 0:
            st.info("No open ports found.")
        else:
            st.dataframe(df[df["status"] == "Open"], width="stretch", height=250)

    with t2:
        st.markdown("<div class='panel'><h3>⚠️ High-Risk Open Ports</h3></div>", unsafe_allow_html=True)
        if high_risk_df.empty:
            st.info("No high-risk open ports found.")
        else:
            st.dataframe(high_risk_df, width="stretch", height=250)

    st.markdown("<div class='panel'><h3>⬇️ Export Results</h3></div>", unsafe_allow_html=True)

    csv_data = to_csv_bytes(df)
    report_bytes = read_file_bytes(st.session_state.report_path)

    d1, d2 = st.columns(2)

    with d1:
        st.download_button(
            label="Download CSV",
            data=csv_data,
            file_name=f"low9ine_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            width="stretch"
        )

    with d2:
        st.download_button(
            label="Download HTML Report",
            data=report_bytes,
            file_name=os.path.basename(st.session_state.report_path),
            mime="text/html",
            width="stretch"
        )

else:
    st.markdown(
        """
        <div class="warning-box">
            Configure the scan settings from the sidebar and click <b>Start Scan</b>.
        </div>
        """,
        unsafe_allow_html=True
    )