import requests

def get_cve(service):
    try:
        url = f"https://cve.circl.lu/api/search/{service}"
        res = requests.get(url, timeout=3)

        if res.status_code != 200:
            return "N/A", "LOW"

        data = res.json()

        if "data" not in data or len(data["data"]) == 0:
            return "N/A", "LOW"

        cve = data["data"][0]

        severity = cve.get("cvss", 0)

        if severity >= 8:
            level = "CRITICAL"
        elif severity >= 6:
            level = "HIGH"
        elif severity >= 4:
            level = "MEDIUM"
        else:
            level = "LOW"

        return cve.get("id", "N/A"), level

    except:
        return "N/A", "LOW"