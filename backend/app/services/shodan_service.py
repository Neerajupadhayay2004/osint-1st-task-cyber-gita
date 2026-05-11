import requests
from app.core.config import settings

BASE_URL = "https://api.shodan.io"

def search_host(ip: str):

    url = f"{BASE_URL}/shodan/host/{ip}"

    params = {
        "key": settings.SHODAN_API_KEY
    }

    response = requests.get(url, params=params)

    return response.json()

