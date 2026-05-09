from fastapi import APIRouter, Depends
from app.services.shodan_service import search_host
from app.services.abuse_service import check_ip
from app.services.vt_service import scan_ip
from app.services.ai_classifier import classify_text
from app.services.gemini_service import gemini_service
from app.core.database import get_db
from sqlalchemy.orm import Session
from app.models import db_models
import json
import re

router = APIRouter()

def clean_input(input_str: str) -> str:
    """Extracts domain or IP from a URL or messy string."""
    # Remove protocols
    cleaned = re.sub(r'^https?://', '', input_str)
    # Remove paths, ports, and queries
    cleaned = cleaned.split('/')[0].split('?')[0].split(':')[0]
    return cleaned.strip()

@router.get("/ip/{ip}")
async def analyze_ip(ip: str, db: Session = Depends(get_db)):
    target = clean_input(ip)
    
    # 1. Gather data from multiple sources
    shodan_data = search_host(target)
    abuse_data = check_ip(target)
    vt_data = scan_ip(target)
    
    # 2. Extract key metrics and boolean indicators
    is_malicious_vt = vt_data.get("malicious_votes", 0) > 0 if not vt_data.get("error") else False
    is_reported_abuse = abuse_data.get("total_reports", 0) > 0 if not abuse_data.get("error") else False
    abuse_score = abuse_data.get("abuse_score", 0) if not abuse_data.get("error") else 0
    
    # 3. AI classification
    analysis_text = f"Target: {target}. "
    if not shodan_data.get("error"):
        analysis_text += f"Org: {shodan_data.get('organization')}. ISP: {shodan_data.get('isp')}. Ports: {shodan_data.get('ports')}. "
    if not abuse_data.get("error"):
        analysis_text += f"Abuse Score: {abuse_score}. Reports: {abuse_data.get('total_reports')}. "
    if not vt_data.get("error"):
        analysis_text += f"VT Reputation: {vt_data.get('reputation')}. Malicious: {vt_data.get('malicious_votes')}. "
        
    ai_analysis = classify_text(analysis_text)
    
    # 4. Use Gemini for deep report
    raw_data = {
        "shodan": shodan_data,
        "abuseipdb": abuse_data,
        "virustotal": vt_data
    }
    gemini_report = await gemini_service.analyze_threat(raw_data)
    
    # 5. Aggregate metrics
    threat_score = 0.0
    if not abuse_data.get("error"):
        threat_score += (abuse_score / 100.0) * 0.4
    if not vt_data.get("error"):
        malicious = vt_data.get("malicious_votes", 0)
        threat_score += (min(malicious, 10) / 10.0) * 0.4
    if ai_analysis.get("threat"):
        threat_score += 0.2
        
    threat_level = "low"
    if threat_score > 0.7: threat_level = "critical"
    elif threat_score > 0.4: threat_level = "high"
    elif threat_score > 0.2: threat_level = "medium"

    # 6. Standardized Professional Response
    result = {
        "target": target,
        "summary": {
            "threat_level": threat_level,
            "threat_score": round(threat_score, 2),
            "is_malicious": is_malicious_vt or is_reported_abuse or ai_analysis.get("threat"),
            "is_whitelisted": abuse_data.get("is_whitelisted", False) if not abuse_data.get("error") else False,
            "total_detections": vt_data.get("malicious_votes", 0) if not vt_data.get("error") else 0,
            "abuse_confidence": abuse_score
        },
        "network": {
            "isp": shodan_data.get("isp") or abuse_data.get("isp"),
            "org": shodan_data.get("organization") or abuse_data.get("domain"),
            "asn": vt_data.get("asn") or "N/A",
            "country": vt_data.get("country") or abuse_data.get("country_code"),
            "ports": shodan_data.get("ports", [])
        },
        "ai_intelligence": {
            "classifier": ai_analysis,
            "gemini_report": gemini_report
        },
        "raw_sources": raw_data
    }
    
    # 7. Save to database
    try:
        db_scan = db_models.Scan(
            target=target,
            scan_type="combined_ip",
            results=result,
            threat_level=threat_level,
            threat_score=threat_score
        )
        db.add(db_scan)
        db.commit()
    except Exception as e:
        logger.error(f"Error saving scan to DB: {e}")

    return result



@router.post("/classify")
def classify(data: dict):
    return classify_text(data["text"])
