from fastapi import APIRouter, HTTPException
from app.services.abuse_service import check_ip

router = APIRouter()

@router.get("/{ip}")
def get_abuse_info(ip: str):
    result = check_ip(ip)
    if not result:
        raise HTTPException(status_code=404, detail="No data found for this IP")
    
    # Standardizing the response if needed or just returning the raw data
    if "data" in result:
        return result["data"]
    
    return result
