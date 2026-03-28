def syn_scan(host, port):
    try:
        from scapy.all import IP, TCP, sr1
        pkt = IP(dst=host)/TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=1, verbose=0)

        if resp is None:
            return port, "filtered"
        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:
                return port, "open"
            else:
                return port, "closed"
    except:
        return port, "filtered"