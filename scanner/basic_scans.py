import socket
from utils.helpers import make_result


def tcp_connect_scan(target_ip: str, port: int, timeout: float = 1.0, requested_scan: str = "TCP Connect"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            banner = ""
            try:
                sock.send(b"HELLO\r\n")
                banner = sock.recv(1024).decode(errors="ignore").strip()[:100]
            except Exception:
                pass
            return make_result(port, "TCP", requested_scan, "Open", banner)
        return make_result(port, "TCP", requested_scan, "Closed")
    except Exception:
        return make_result(port, "TCP", requested_scan, "Filtered")
    finally:
        sock.close()


def udp_scan(target_ip: str, port: int, timeout: float = 2.0, requested_scan: str = "UDP Probe"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        sock.sendto(b"", (target_ip, port))
        try:
            data, _ = sock.recvfrom(1024)
            banner = data.decode(errors="ignore")[:100] if data else ""
            return make_result(port, "UDP", requested_scan, "Responsive", banner)
        except socket.timeout:
            return make_result(port, "UDP", requested_scan, "Open|Filtered")
        except Exception:
            return make_result(port, "UDP", requested_scan, "Filtered")
    except Exception:
        return make_result(port, "UDP", requested_scan, "Filtered")
    finally:
        sock.close()