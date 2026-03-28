import socket

def grab_banner(host, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((host, port))

        if port == 80:
            s.send(b"GET / HTTP/1.1\r\nHost:test\r\n\r\n")

        data = s.recv(1024).decode(errors="ignore")
        s.close()
        return data.strip()
    except:
        return "N/A"