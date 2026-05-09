from fastapi import APIRouter, HTTPException
from app.services.abuse_service import check_ip

router = APIRouter()

@router.get("/{ip}")
def get_abuse_info(ip: str):
    result = check_ip(ip)
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    return result
