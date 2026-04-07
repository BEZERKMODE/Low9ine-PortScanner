import socket

from intelligence.risk_ai import enrich_finding
from scanner.fingerprint import grab_banner, get_http_title
from utils.helpers import make_result, get_service_name


def tcp_connect_scan(ip, port, timeout=1.0, requested_scan="TCP Connect"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((ip, port))

        if result == 0:
            service = get_service_name(port)
            banner = grab_banner(ip, port, timeout)

            if port in [80, 8080, 8000, 8443]:
                title = get_http_title(ip, port, timeout)
                if title:
                    if banner:
                        banner = f"{banner} | HTTP Title: {title}"[:260]
                    else:
                        banner = f"HTTP Title: {title}"[:260]

            intelligence = enrich_finding(
                port=port,
                protocol="TCP",
                service=service,
                state="Open",
                banner=banner
            )

            return make_result(
                port=port,
                protocol="TCP",
                scan=requested_scan,
                state="Open",
                banner=banner,
                risk=intelligence["risk"],
                cvss=intelligence["cvss"],
                threats=intelligence["threats"],
                mitre=intelligence["mitre"],
                simulation=intelligence["simulation"],
                focus=intelligence["focus"],
            )

        return make_result(
            port=port,
            protocol="TCP",
            scan=requested_scan,
            state="Closed",
        )

    except Exception:
        return make_result(
            port=port,
            protocol="TCP",
            scan=requested_scan,
            state="Filtered",
        )
    finally:
        sock.close()


def udp_probe_scan(ip, port, timeout=2.0, requested_scan="UDP Probe"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        sock.sendto(b"", (ip, port))

        try:
            data, _ = sock.recvfrom(1024)
            banner = data.decode(errors="ignore").strip()[:220] if data else ""
            service = get_service_name(port)

            intelligence = enrich_finding(
                port=port,
                protocol="UDP",
                service=service,
                state="Responsive",
                banner=banner
            )

            return make_result(
                port=port,
                protocol="UDP",
                scan=requested_scan,
                state="Responsive",
                banner=banner,
                risk=intelligence["risk"],
                cvss=intelligence["cvss"],
                threats=intelligence["threats"],
                mitre=intelligence["mitre"],
                simulation=intelligence["simulation"],
                focus=intelligence["focus"],
            )

        except socket.timeout:
            service = get_service_name(port)
            intelligence = enrich_finding(
                port=port,
                protocol="UDP",
                service=service,
                state="Open|Filtered",
                banner=""
            )

            return make_result(
                port=port,
                protocol="UDP",
                scan=requested_scan,
                state="Open|Filtered",
                banner="",
                risk=intelligence["risk"],
                cvss=intelligence["cvss"],
                threats=intelligence["threats"],
                mitre=intelligence["mitre"],
                simulation=intelligence["simulation"],
                focus=intelligence["focus"],
            )

    except Exception:
        return make_result(
            port=port,
            protocol="UDP",
            scan=requested_scan,
            state="Filtered",
        )
    finally:
        sock.close()