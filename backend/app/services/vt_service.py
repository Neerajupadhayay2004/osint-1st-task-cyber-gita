import requests
from app.core.config import settings
import logging
import base64

logger = logging.getLogger(__name__)

BASE_URL = "https://www.virustotal.com/api/v3"

def scan_resource(resource_type: str, resource_value: str):
    """
    Scans a resource (ip, domain, file hash, or url) using VirusTotal v3 API.
    """
    if not settings.VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not configured"}

    headers = {
        "x-apikey": settings.VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }

    v = resource_value.strip()
    path = ""
    
    if resource_type == "ip":
        path = f"ip_addresses/{v}"
    elif resource_type == "domain":
        path = f"domains/{v}"
    elif resource_type == "hash":
        path = f"files/{v}"
    elif resource_type == "url":
        # VT URL IDs are base64 encoded without padding
        url_id = base64.urlsafe_b64encode(v.encode()).decode().strip("=")
        path = f"urls/{url_id}"
    else:
        return {"error": f"Unsupported resource type: {resource_type}"}

    try:
        response = requests.get(
            f"{BASE_URL}/{path}",
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        attributes = data.get("attributes", {})
        
        return {
            "id": data.get("id"),
            "type": data.get("type"),
            "reputation": attributes.get("reputation"),
            "last_analysis_stats": attributes.get("last_analysis_stats", {}),
            "malicious_votes": attributes.get("last_analysis_stats", {}).get("malicious", 0),
            "suspicious_votes": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
            "harmless_votes": attributes.get("last_analysis_stats", {}).get("harmless", 0),
            "tags": attributes.get("tags", []),
            "asn": attributes.get("asn"),
            "country": attributes.get("country"),
            "raw": data
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"VirusTotal API error: {e}")
        return {"error": str(e)}

def scan_ip(ip):
    return scan_resource("ip", ip)

# Also adding these for backward compatibility with older routes
def analyze_ip(ip): return scan_resource("ip", ip)
def analyze_domain(domain): return scan_resource("domain", domain)
def analyze_url(url): return scan_resource("url", url)
