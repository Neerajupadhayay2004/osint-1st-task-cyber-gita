import requests
from app.core.config import settings

URL = "https://api.abuseipdb.com/api/v2/check"

def check_ip(ip):

    headers = {
        "Key": settings.ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(URL, headers=headers, params=params)

    return response.json()

