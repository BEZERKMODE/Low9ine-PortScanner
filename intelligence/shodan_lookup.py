import requests
import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

def shodan_lookup(ip):
    api_key = os.getenv("SHODAN_API_KEY")

    if not api_key:
        return {
            "error": "No API key found. Check your .env file."
        }

    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        response = requests.get(url, timeout=5)

        if response.status_code != 200:
            return {
                "error": f"Shodan API error: {response.status_code}"
            }

        data = response.json()

        return {
            "IP": ip,
            "Organization": data.get("org", "N/A"),
            "ISP": data.get("isp", "N/A"),
            "OS": data.get("os", "N/A"),
            "Country": data.get("country_name", "N/A"),
            "City": data.get("city", "N/A"),
            "Open Ports": data.get("ports", []),
            "Hostnames": data.get("hostnames", [])
        }

    except Exception as e:
        return {
            "error": str(e)
        }