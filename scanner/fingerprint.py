import socket


def grab_banner(target_ip: str, port: int, timeout: float = 1.5) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((target_ip, port))

        if port in [80, 8080, 8000, 8443]:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {target_ip}\r\n\r\n".encode())
        elif port in [21, 22, 25, 110, 143]:
            pass
        else:
            sock.sendall(b"\r\n")

        data = sock.recv(1024)
        return data.decode(errors="ignore").strip()[:220]
    except Exception:
        return ""
    finally:
        sock.close()


def get_http_title(target_ip: str, port: int, timeout: float = 2.0) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((target_ip, port))
        request = f"GET / HTTP/1.0\r\nHost: {target_ip}\r\n\r\n".encode()
        sock.sendall(request)

        chunks = []
        for _ in range(3):
            try:
                part = sock.recv(4096)
                if not part:
                    break
                chunks.append(part)
                if b"</title>" in part.lower():
                    break
            except Exception:
                break

        data = b"".join(chunks).decode(errors="ignore")
        lower = data.lower()

        if "<title>" in lower and "</title>" in lower:
            start = lower.find("<title>") + 7
            end = lower.find("</title>")
            return data[start:end].strip()[:120]

        return ""
    except Exception:
        return ""
    finally:
        sock.close()