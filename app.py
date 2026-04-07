import streamlit as st
import pandas as pd
import socket
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# Scapy imports for advanced scans
try:
    from scapy.all import IP, TCP, UDP, ICMP, sr1, send
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


# -----------------------------
# PAGE CONFIG
# -----------------------------
st.set_page_config(
    page_title="LOW9INE ELITE PORT SCANNER",
    page_icon="💀",
    layout="wide"
)

# -----------------------------
# CUSTOM CSS - HACKER STYLE
# -----------------------------
st.markdown("""
<style>
html, body, [class*="css"] {
    background-color: #05070d;
    color: #d7ffe8;
    font-family: Consolas, monospace;
}

.main {
    background: linear-gradient(180deg, #05070d 0%, #08111f 100%);
}

.block-container {
    padding-top: 1rem;
    padding-bottom: 2rem;
}

h1, h2, h3 {
    color: #00ffae !important;
    text-shadow: 0 0 8px rgba(0,255,174,0.25);
}

.stTextInput > div > div > input,
.stNumberInput input,
.stSelectbox div[data-baseweb="select"] > div,
.stMultiSelect div[data-baseweb="select"] > div {
    background-color: #0b1220 !important;
    color: #e6fff6 !important;
    border: 1px solid #00ffae33 !important;
    border-radius: 10px !important;
}

.stButton > button {
    background: linear-gradient(90deg, #00ffae, #00d9ff);
    color: black !important;
    font-weight: bold;
    border: none;
    border-radius: 12px;
    padding: 0.6rem 1.4rem;
    box-shadow: 0 0 18px rgba(0,255,174,0.25);
}

.stButton > button:hover {
    transform: scale(1.02);
    transition: 0.2s ease;
}

.metric-card {
    background: rgba(8, 17, 31, 0.9);
    border: 1px solid rgba(0,255,174,0.18);
    border-radius: 16px;
    padding: 16px;
    text-align: center;
    box-shadow: 0 0 14px rgba(0,255,174,0.08);
}

.metric-title {
    color: #9bd9c6;
    font-size: 14px;
}

.metric-value {
    color: #00ffae;
    font-size: 28px;
    font-weight: bold;
}

.small-note {
    color: #91a3b0;
    font-size: 12px;
}

.scan-box {
    background: #09111d;
    padding: 14px;
    border-radius: 12px;
    border: 1px solid #1d2d44;
}

.success-port {
    color: #00ff88;
    font-weight: bold;
}

.closed-port {
    color: #ff5e5e;
    font-weight: bold;
}

.filtered-port {
    color: #ffd166;
    font-weight: bold;
}
</style>
""", unsafe_allow_html=True)


# -----------------------------
# HELPERS
# -----------------------------
COMMON_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCBIND",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    137: "NETBIOS-NS",
    138: "NETBIOS-DGM",
    139: "NETBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMPTRAP",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "SYSLOG",
    515: "LPD",
    587: "SMTP SUBMISSION",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE",
    1723: "PPTP",
    2049: "NFS",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    5900: "VNC",
    6379: "REDIS",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}

HIGH_RISK_PORTS = {21, 23, 135, 137, 138, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379}


def resolve_target(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def validate_ip_or_host(target: str) -> bool:
    if not target:
        return False
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return True


def get_service_name(port: int) -> str:
    return COMMON_PORTS.get(port, "Unknown")


def get_risk_level(port: int) -> str:
    if port in HIGH_RISK_PORTS:
        return "High"
    elif port in {80, 443, 53, 22, 25, 110, 143, 993, 995}:
        return "Medium"
    return "Low"


def parse_ports(port_text: str):
    ports = set()
    chunks = port_text.split(",")
    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-")
            start = int(start.strip())
            end = int(end.strip())
            for p in range(start, end + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(chunk)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(list(ports))


# -----------------------------
# BASIC TCP CONNECT SCAN
# -----------------------------
def tcp_connect_scan(target_ip: str, port: int, timeout: float = 1.0):
    result = {
        "Port": port,
        "Protocol": "TCP",
        "Scan Type": "TCP Connect",
        "State": "Closed",
        "Service": get_service_name(port),
        "Risk": get_risk_level(port),
        "Banner": ""
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        code = sock.connect_ex((target_ip, port))
        if code == 0:
            result["State"] = "Open"
            try:
                sock.send(b"HELLO\r\n")
                banner = sock.recv(1024).decode(errors="ignore").strip()
                result["Banner"] = banner[:100]
            except Exception:
                pass
        else:
            result["State"] = "Closed"
    except Exception:
        result["State"] = "Filtered"
    finally:
        sock.close()

    return result


# -----------------------------
# UDP SCAN
# -----------------------------
def udp_scan(target_ip: str, port: int, timeout: float = 2.0):
    result = {
        "Port": port,
        "Protocol": "UDP",
        "Scan Type": "UDP Scan",
        "State": "Open|Filtered",
        "Service": get_service_name(port),
        "Risk": get_risk_level(port),
        "Banner": ""
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"", (target_ip, port))
        try:
            data, _ = sock.recvfrom(1024)
            if data:
                result["State"] = "Open"
                result["Banner"] = data.decode(errors="ignore")[:100]
        except socket.timeout:
            result["State"] = "Open|Filtered"
        except Exception:
            result["State"] = "Filtered"
        finally:
            sock.close()
    except Exception:
        result["State"] = "Filtered"

    return result


# -----------------------------
# RAW PACKET SCANS WITH SCAPY
# -----------------------------
def syn_scan(target_ip: str, port: int, timeout: float = 1.5):
    result = {
        "Port": port,
        "Protocol": "TCP",
        "Scan Type": "SYN Scan",
        "State": "Filtered",
        "Service": get_service_name(port),
        "Risk": get_risk_level(port),
        "Banner": ""
    }

    if not SCAPY_AVAILABLE:
        result["State"] = "Scapy Missing"
        return result

    try:
        pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0)

        if resp is None:
            result["State"] = "Filtered"
        elif resp.haslayer(TCP):
            flags = resp[TCP].flags
            if flags == 0x12:  # SYN-ACK
                result["State"] = "Open"
                send(IP(dst=target_ip) / TCP(dport=port, flags="R"), verbose=0)
            elif flags == 0x14:  # RST-ACK
                result["State"] = "Closed"
        elif resp.haslayer(ICMP):
            result["State"] = "Filtered"
    except Exception:
        result["State"] = "Error"

    return result


def ack_scan(target_ip: str, port: int, timeout: float = 1.5):
    result = {
        "Port": port,
        "Protocol": "TCP",
        "Scan Type": "ACK Scan",
        "State": "Filtered",
        "Service": get_service_name(port),
        "Risk": get_risk_level(port),
        "Banner": ""
    }

    if not SCAPY_AVAILABLE:
        result["State"] = "Scapy Missing"
        return result

    try:
        pkt = IP(dst=target_ip) / TCP(dport=port, flags="A")
        resp = sr1(pkt, timeout=timeout, verbose=0)

        if resp is None:
            result["State"] = "Filtered"
        elif resp.haslayer(TCP):
            if resp[TCP].flags == 0x4:
                result["State"] = "Unfiltered"
            else:
                result["State"] = "Filtered"
        elif resp.haslayer(ICMP):
            result["State"] = "Filtered"
    except Exception:
        result["State"] = "Error"

    return result


def null_scan(target_ip: str, port: int, timeout: float = 1.5):
    result = {
        "Port": port,
        "Protocol": "TCP",
        "Scan Type": "NULL Scan",
        "State": "Open|Filtered",
        "Service": get_service_name(port),
        "Risk": get_risk_level(port),
        "Banner": ""
    }

    if not SCAPY_AVAILABLE:
        result["State"] = "Scapy Missing"
        return result

    try:
        pkt = IP(dst=target_ip) / TCP(dport=port, flags="")
        resp = sr1(pkt, timeout=timeout, verbose=0)

        if resp is None:
            result["State"] = "Open|Filtered"
        elif resp.haslayer(TCP) and resp[TCP].flags == 0x14:
            result["State"] = "Closed"
        elif resp.haslayer(ICMP):
            result["State"] = "Filtered"
    except Exception:
        result["State"] = "Error"

    return result


def xmas_scan(target_ip: str, port: int, timeout: float = 1.5):
    result = {
        "Port": port,
        "Protocol": "TCP",
        "Scan Type": "XMAS Scan",
        "State": "Open|Filtered",
        "Service": get_service_name(port),
        "Risk": get_risk_level(port),
        "Banner": ""
    }

    if not SCAPY_AVAILABLE:
        result["State"] = "Scapy Missing"
        return result

    try:
        pkt = IP(dst=target_ip) / TCP(dport=port, flags="FPU")
        resp = sr1(pkt, timeout=timeout, verbose=0)

        if resp is None:
            result["State"] = "Open|Filtered"
        elif resp.haslayer(TCP) and resp[TCP].flags == 0x14:
            result["State"] = "Closed"
        elif resp.haslayer(ICMP):
            result["State"] = "Filtered"
    except Exception:
        result["State"] = "Error"

    return result


def window_scan(target_ip: str, port: int, timeout: float = 1.5):
    result = {
        "Port": port,
        "Protocol": "TCP",
        "Scan Type": "Window Scan",
        "State": "Closed",
        "Service": get_service_name(port),
        "Risk": get_risk_level(port),
        "Banner": ""
    }

    if not SCAPY_AVAILABLE:
        result["State"] = "Scapy Missing"
        return result

    try:
        pkt = IP(dst=target_ip) / TCP(dport=port, flags="A")
        resp = sr1(pkt, timeout=timeout, verbose=0)

        if resp is None:
            result["State"] = "Filtered"
        elif resp.haslayer(TCP):
            if resp[TCP].flags == 0x4:
                if resp[TCP].window > 0:
                    result["State"] = "Open"
                else:
                    result["State"] = "Closed"
        elif resp.haslayer(ICMP):
            result["State"] = "Filtered"
    except Exception:
        result["State"] = "Error"

    return result


def maimon_scan(target_ip: str, port: int, timeout: float = 1.5):
    result = {
        "Port": port,
        "Protocol": "TCP",
        "Scan Type": "Maimon Scan",
        "State": "Open|Filtered",
        "Service": get_service_name(port),
        "Risk": get_risk_level(port),
        "Banner": ""
    }

    if not SCAPY_AVAILABLE:
        result["State"] = "Scapy Missing"
        return result

    try:
        pkt = IP(dst=target_ip) / TCP(dport=port, flags="FA")
        resp = sr1(pkt, timeout=timeout, verbose=0)

        if resp is None:
            result["State"] = "Open|Filtered"
        elif resp.haslayer(TCP) and resp[TCP].flags == 0x14:
            result["State"] = "Closed"
        elif resp.haslayer(ICMP):
            result["State"] = "Filtered"
    except Exception:
        result["State"] = "Error"

    return result


# -----------------------------
# SCAN DISPATCHER
# -----------------------------
def scan_dispatch(target_ip: str, port: int, scan_type: str, timeout: float):
    if scan_type == "TCP Connect":
        return tcp_connect_scan(target_ip, port, timeout)
    elif scan_type == "SYN Scan":
        return syn_scan(target_ip, port, timeout)
    elif scan_type == "UDP Scan":
        return udp_scan(target_ip, port, timeout)
    elif scan_type == "ACK Scan":
        return ack_scan(target_ip, port, timeout)
    elif scan_type == "NULL Scan":
        return null_scan(target_ip, port, timeout)
    elif scan_type == "XMAS Scan":
        return xmas_scan(target_ip, port, timeout)
    elif scan_type == "Window Scan":
        return window_scan(target_ip, port, timeout)
    elif scan_type == "Maimon Scan":
        return maimon_scan(target_ip, port, timeout)
    else:
        return {
            "Port": port,
            "Protocol": "TCP",
            "Scan Type": scan_type,
            "State": "Unknown",
            "Service": get_service_name(port),
            "Risk": get_risk_level(port),
            "Banner": ""
        }


# -----------------------------
# UI HEADER
# -----------------------------
st.markdown("<h1>💀 LOW9INE ELITE PORT SCANNER</h1>", unsafe_allow_html=True)
st.markdown(
    "<div class='scan-box'>Advanced penetration testing style scanner with TCP, UDP, SYN, ACK, NULL, XMAS, Window and Maimon scans.</div>",
    unsafe_allow_html=True
)

col1, col2, col3 = st.columns(3)
with col1:
    target = st.text_input("🎯 Target IP / Domain", placeholder="scanme.nmap.org or 192.168.1.1")
with col2:
    port_input = st.text_input("🔌 Ports", value="20-100")
with col3:
    timeout = st.number_input("⏳ Timeout (seconds)", min_value=0.5, max_value=10.0, value=1.0, step=0.5)

scan_type = st.selectbox(
    "🛠 Select Scan Type",
    [
        "TCP Connect",
        "SYN Scan",
        "UDP Scan",
        "ACK Scan",
        "NULL Scan",
        "XMAS Scan",
        "Window Scan",
        "Maimon Scan"
    ]
)

threads = st.slider("⚡ Threads", min_value=10, max_value=300, value=100, step=10)

st.markdown(
    "<p class='small-note'>For raw scans on Windows, run PowerShell as Administrator and install Npcap.</p>",
    unsafe_allow_html=True
)

# -----------------------------
# START SCAN
# -----------------------------
if st.button("🚀 START SCAN"):
    if not validate_ip_or_host(target):
        st.error("Invalid target.")
        st.stop()

    target_ip = resolve_target(target)
    if not target_ip:
        st.error("Could not resolve target hostname.")
        st.stop()

    try:
        ports = parse_ports(port_input)
        if not ports:
            st.error("No valid ports found.")
            st.stop()
    except Exception:
        st.error("Invalid port format. Example: 22,80,443 or 1-1000")
        st.stop()

    st.info(f"Target resolved: {target} → {target_ip}")
    st.write(f"Running **{scan_type}** on **{len(ports)} ports** ...")

    results = []
    progress = st.progress(0)
    live_output = st.empty()

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_dispatch, target_ip, port, scan_type, timeout): port
            for port in ports
        }

        completed = 0
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            completed += 1
            progress.progress(completed / len(ports))

            temp_df = pd.DataFrame(results).sort_values(by="Port")
            live_output.dataframe(temp_df, width="stretch")

    end_time = time.time()
    duration = round(end_time - start_time, 2)

    df = pd.DataFrame(results).sort_values(by="Port").reset_index(drop=True)

    if df.empty:
        st.warning("No results.")
        st.stop()

    open_count = len(df[df["State"].isin(["Open", "Unfiltered", "Open|Filtered"])])
    closed_count = len(df[df["State"] == "Closed"])
    filtered_count = len(df[df["State"].isin(["Filtered", "Error", "Scapy Missing"])])

    # Summary cards
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Target</div>
            <div class="metric-value" style="font-size:20px;">{target_ip}</div>
        </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Open / Interesting</div>
            <div class="metric-value">{open_count}</div>
        </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Closed</div>
            <div class="metric-value">{closed_count}</div>
        </div>
        """, unsafe_allow_html=True)
    with c4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Filtered / Other</div>
            <div class="metric-value">{filtered_count}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("## 📊 Scan Results")
    st.dataframe(df, width="stretch")

    st.markdown("## 🎯 Open / Interesting Ports")
    interesting_df = df[df["State"].isin(["Open", "Unfiltered", "Open|Filtered"])].copy()

    if not interesting_df.empty:
        def highlight_risk(row):
            if row["Risk"] == "High":
                return ["background-color: rgba(255,0,0,0.20)"] * len(row)
            elif row["Risk"] == "Medium":
                return ["background-color: rgba(255,165,0,0.18)"] * len(row)
            return ["background-color: rgba(0,255,174,0.10)"] * len(row)

        st.dataframe(
            interesting_df.style.apply(highlight_risk, axis=1),
            width="stretch"
        )
    else:
        st.warning("No open or interesting ports found.")

    st.markdown("## 📥 Download Report")
    csv_data = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="Download CSV Report",
        data=csv_data,
        file_name=f"low9ine_scan_{target_ip}_{scan_type.replace(' ', '_').lower()}.csv",
        mime="text/csv"
    )

    st.success(f"Scan completed in {duration} seconds.")

# -----------------------------
# FOOTER
# -----------------------------
st.markdown("---")
st.markdown(
    "<p class='small-note'>Use only on systems you own or are explicitly authorized to test.</p>",
    unsafe_allow_html=True
)