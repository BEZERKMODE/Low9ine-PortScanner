from intelligence.cve_db import DEFAULT_THREAT, SERVICE_THREAT_DB


def normalize_service(service: str) -> str:
    return (service or "Unknown").strip().upper()


def calculate_risk_label(cvss: float, state: str) -> str:
    if state not in {"Open", "Responsive", "Open|Filtered", "Unfiltered", "Open (Window)"}:
        return "Low"

    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    return "Low"


def enrich_finding(port: int, protocol: str, service: str, state: str, banner: str = ""):
    key = normalize_service(service)
    threat = SERVICE_THREAT_DB.get(key, DEFAULT_THREAT)

    cvss = float(threat["cvss"])

    if port in {23, 445, 3389, 1433, 1521, 3306, 5432, 6379, 27017}:
        cvss = min(10.0, cvss + 0.4)

    if protocol == "UDP" and state == "Open|Filtered":
        cvss = max(3.5, cvss - 0.7)

    if "admin" in (banner or "").lower():
        cvss = min(10.0, cvss + 0.5)

    risk = calculate_risk_label(cvss, state)

    return {
        "risk": risk,
        "cvss": round(cvss, 1),
        "threats": threat["threats"],
        "mitre": threat["mitre"],
        "simulation": threat["simulation"],
        "focus": threat["focus"],
    }