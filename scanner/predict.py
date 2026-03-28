COMMON = [21,22,23,25,53,80,110,139,143,443,445,3389]

def predict_ports(results):
    open_ports = [p for p,s in results if s=="open"]
    return [p for p in COMMON if p not in open_ports][:5]