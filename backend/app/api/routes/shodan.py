from fastapi import APIRouter, HTTPException
from app.services.shodan_service import search_host

router = APIRouter()

@router.get("/{ip}")
def get_shodan_info(ip: str):
    result = search_host(ip)
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    return result
