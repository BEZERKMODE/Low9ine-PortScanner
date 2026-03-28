import socket

def scan_ports_tcp(host, ports):
    results = []
    for port in ports:
        try:
            sock = socket.socket()
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                results.append((port, "open"))
            else:
                results.append((port, "closed"))
        except:
            results.append((port, "filtered"))
    return results