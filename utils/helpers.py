import ipaddress
import socket

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
    587: "SMTP Submission",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE",
    1723: "PPTP",
    1883: "MQTT",
    2049: "NFS",
    2375: "DOCKER",
    2376: "DOCKER-TLS",
    3306: "MYSQL",
    3389: "RDP",
    5000: "DEV-SERVER",
    5432: "POSTGRESQL",
    5683: "COAP",
    5900: "VNC",
    5985: "WINRM-HTTP",
    5986: "WINRM-HTTPS",
    6379: "REDIS",
    6443: "KUBERNETES-API",
    8000: "HTTP-ALT",
    8001: "HTTP-ALT",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    8888: "HTTP-ALT",
    9000: "HTTP-ALT",
    10250: "KUBELET",
    27017: "MONGODB",
}


def resolve_target(target: str):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def validate_target(target: str) -> bool:
    if not target:
        return False
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return True


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
            if start > end:
                start, end = end, start
            for p in range(start, end + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(chunk)
            if 1 <= p <= 65535:
                ports.add(p)

    return sorted(ports)


def get_service_name(port: int) -> str:
    return COMMON_PORTS.get(port, "Unknown")


def make_result(
    port,
    protocol,
    scan,
    state,
    banner="",
    risk="Low",
    cvss=0.0,
    threats=None,
    mitre=None,
    simulation="Recon",
    focus="General Exposure",
):
    return {
        "Port": port,
        "Protocol": protocol,
        "Scan": scan,
        "State": state,
        "Service": get_service_name(port),
        "Risk": risk,
        "CVSS": cvss,
        "Simulation": simulation,
        "Focus": focus,
        "Threats": threats or [],
        "MITRE": mitre or [],
        "Banner": banner,
    }


def summarize_findings(df):
    if df.empty:
        return "No results were produced."

    open_like = df[df["State"].isin(["Open", "Responsive", "Open|Filtered", "Unfiltered", "Open (Window)"])]
    critical = df[df["Risk"] == "Critical"]
    high = df[df["Risk"] == "High"]

    top_services = (
        open_like["Service"].value_counts().head(5).to_dict()
        if not open_like.empty else {}
    )

    if not open_like.empty:
        services_text = ", ".join([f"{k}={v}" for k, v in top_services.items()])
        return (
            f"Live enumeration completed. Open or interesting findings: {len(open_like)}. "
            f"High severity findings: {len(high)}. Critical findings: {len(critical)}. "
            f"Most observed exposed services: {services_text if services_text else 'none'}."
        )

    return "Enumeration completed. No open or interesting ports were identified in the selected range."