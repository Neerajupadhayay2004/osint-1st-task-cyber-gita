from fastapi import APIRouter

from app.services.threat_intelligence import (
    threat_intel_service
)

router = APIRouter()

# ---------------------------------------------------
# Latest CVEs
# ---------------------------------------------------

@router.get("/cves")
async def latest_cves():

    return await threat_intel_service.get_latest_cves()

# ---------------------------------------------------
# Search CVEs
# ---------------------------------------------------

<<<<<<< HEAD
@router.get("/cves/search")
async def search_cves(query: str):
=======
@router.get("/cves/search/{query}")
async def search_cves(query: str):

>>>>>>> d0f073da67d0618f343f8ec0c7a223c3526914d5
    return await threat_intel_service.search_cves(query)

# ---------------------------------------------------
# Malware Feeds
# ---------------------------------------------------

@router.get("/malware")
async def malware_feeds():

    return await threat_intel_service.get_malware_feeds()

# ---------------------------------------------------
# Email Breach Intelligence
# ---------------------------------------------------

@router.get("/breaches/{email}")
async def check_breach(email: str):

    result = await threat_intel_service.search_breaches(email)

    return {
        "ok": True,
        "data": result
    }