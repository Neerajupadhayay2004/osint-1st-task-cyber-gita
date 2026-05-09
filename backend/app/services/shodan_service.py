import requests
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

BASE_URL = "https://api.shodan.io"

def search_host(ip: str):
    if not settings.SHODAN_API_KEY:
        return {"error": "SHODAN_API_KEY not configured"}
        
    url = f"{BASE_URL}/shodan/host/{ip}"
    params = {"key": settings.SHODAN_API_KEY}

    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        # Simplify response for better consumption
        return {
            "ip": data.get("ip_str"),
            "organization": data.get("org"),
            "isp": data.get("isp"),
            "ports": data.get("ports", []),
            "os": data.get("os"),
            "hostnames": data.get("hostnames", []),
            "vulns": data.get("vulns", []),
            "last_update": data.get("last_update"),
            "raw": data # Keep raw data just in case
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"Shodan API error: {e}")
        return {"error": str(e)}


