# utils/ai_risk.py

def calculate_risk(port, status, severity):
    score = 0

    # Base risk if open
    if status == "open":
        score += 40

    # CVE severity weight
    if severity == "CRITICAL":
        score += 40
    elif severity == "HIGH":
        score += 30
    elif severity == "MEDIUM":
        score += 20
    else:
        score += 10

    # High-risk ports bonus
    if port in [21, 22, 23, 3389, 445]:
        score += 20

    # Final level
    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level