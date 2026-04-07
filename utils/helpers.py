import socket
import ipaddress

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


def get_risk_level(port: int) -> str:
    if port in HIGH_RISK_PORTS:
        return "High"
    elif port in {22, 25, 53, 80, 110, 143, 443, 993, 995}:
        return "Medium"
    return "Low"


def make_result(port, protocol, scan_type, state, banner=""):
    return {
        "Port": port,
        "Protocol": protocol,
        "Scan Type": scan_type,
        "State": state,
        "Service": get_service_name(port),
        "Risk": get_risk_level(port),
        "Banner": banner,
    }