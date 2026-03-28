import requests

def geo(ip):
    try:
        d = requests.get(f"http://ip-api.com/json/{ip}").json()
        return d.get("country"), d.get("isp")
    except:
        return "N/A","N/A"