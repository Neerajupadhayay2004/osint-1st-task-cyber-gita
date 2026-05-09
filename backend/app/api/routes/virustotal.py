from fastapi import APIRouter
from pydantic import BaseModel
from app.services.vt_service import (
    analyze_ip,
    analyze_domain,
    analyze_url
)

router = APIRouter()

class URLRequest(BaseModel):
    url: str

@router.get("/ip/{ip}")
def vt_ip(ip: str):
    return analyze_ip(ip)

@router.get("/domain/{domain}")
def vt_domain(domain: str):
    return analyze_domain(domain)

@router.post("/url")
def vt_url(data: URLRequest):
    return analyze_url(data.url)