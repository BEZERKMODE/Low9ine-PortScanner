# utils/recon.py

import socket


# ---------------- SUBDOMAIN DISCOVERY ----------------
def find_subdomains(domain):
    """
    Extended subdomain brute force
    """
    subdomains = []

    wordlist = [
        "www","mail","ftp","test","dev","api","admin",
        "portal","vpn","blog","shop","secure","beta",
        "staging","internal","gateway","cdn","img",
        "static","files","data","app","server","ns1","ns2"
    ]

    for sub in wordlist:
        subdomain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            subdomains.append(subdomain)
        except:
            continue

    return list(set(subdomains))


# ---------------- DNS LOOKUP ----------------
def dns_lookup(domain):
    """
    Get DNS + reverse hostname info
    """
    data = {}

    try:
        ip = socket.gethostbyname(domain)
        data["IP"] = ip
    except:
        data["IP"] = "Unavailable"
        return data

    try:
        hostname = socket.gethostbyaddr(ip)[0]
        data["Hostname"] = hostname
    except:
        data["Hostname"] = "Unavailable"

    return data


# ---------------- BASIC WHOIS (SAFE VERSION) ----------------
def whois_lookup(domain):
    """
    Lightweight WHOIS-style info (no API)
    """
    try:
        ip = socket.gethostbyname(domain)

        return f"""
Domain: {domain}
Resolved IP: {ip}

Info:
- Lightweight lookup (no API used)
- Use Shodan panel for deeper intelligence
"""
    except:
        return "WHOIS lookup failed"


# ---------------- PORT HINT INTELLIGENCE ----------------
def port_intelligence():
    """
    Common interesting ports to scan first
    """
    return [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]


# ---------------- FULL RECON WRAPPER ----------------
def run_recon(domain):
    """
    Run full recon pipeline
    """
    result = {}

    result["subdomains"] = find_subdomains(domain)
    result["dns"] = dns_lookup(domain)
    result["whois"] = whois_lookup(domain)
    result["priority_ports"] = port_intelligence()

    return result