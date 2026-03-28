COMMON = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",
    53:"DNS",80:"HTTP",443:"HTTPS",
    3306:"MySQL",3389:"RDP"
}

def detect_service(port):
    return COMMON.get(port, "Unknown")