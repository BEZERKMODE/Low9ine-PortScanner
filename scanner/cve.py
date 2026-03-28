import requests

def get_cve(service):
    try:
        r = requests.get(f"https://cve.circl.lu/api/search/{service}",timeout=3).json()
        return r[0]["id"] if r else "None"
    except:
        return "N/A"