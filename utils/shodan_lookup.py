import requests

# 🔑 YOUR SHODAN KEY (ALREADY ADDED)
API_KEY = "bEzquV58CkmRELrEr1hIxNilnwJBvOnY"

def shodan_lookup(ip):
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={API_KEY}"
        res = requests.get(url, timeout=3)

        if res.status_code != 200:
            return "No Data"

        data = res.json()

        org = data.get("org", "Unknown Org")
        isp = data.get("isp", "Unknown ISP")
        country = data.get("country_name", "Unknown Country")

        return f"{org} | {isp} | {country}"

    except:
        return "Unavailable"