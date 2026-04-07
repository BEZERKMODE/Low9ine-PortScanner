import socket
import time


def is_host_reachable_tcp(target_ip: str, timeout: float = 1.0):
    common_ports = [80, 443, 22, 53]
    start = time.time()

    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                sock.close()
                return {
                    "reachable": True,
                    "method": f"TCP {port}",
                    "latency_ms": round((time.time() - start) * 1000, 2),
                }
        except Exception:
            pass
        finally:
            sock.close()

    return {
        "reachable": False,
        "method": "No response",
        "latency_ms": round((time.time() - start) * 1000, 2),
    }