VULNS = {
    21:"FTP brute-force risk",
    23:"Telnet insecure",
    3389:"RDP exploit risk"
}

def check_vuln(port):
    return VULNS.get(port, "None")