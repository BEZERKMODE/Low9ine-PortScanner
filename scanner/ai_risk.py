def risk_score(port, status, service):
    score = 0
    if status == "open": score += 5
    if service in ["FTP","Telnet"]: score += 3
    if port in [22,3389,445]: score += 2
    return min(score,10)