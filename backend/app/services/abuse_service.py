import requests
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

URL = "https://api.abuseipdb.com/api/v2/check"

def check_ip(ip):
    if not settings.ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY not configured"}

    headers = {
        "Key": settings.ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": True
    }

    try:
        response = requests.get(URL, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json().get("data", {})
        
        return {
            "ip": data.get("ipAddress"),
            "abuse_score": data.get("abuseConfidenceScore"),
            "is_whitelisted": data.get("isWhitelisted"),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
            "raw": data
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"AbuseIPDB API error: {e}")
        return {"error": str(e)}


