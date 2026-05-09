from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models import db_models
from app.services.reporting import reporting_service
from typing import Any, Dict

router = APIRouter()

@router.get("/summary")
def get_analytics_summary(db: Session = Depends(get_db)):
    """Get high-level analytics summary for the dashboard."""
    total_scans = db.query(db_models.Scan).count()
    high_threats = db.query(db_models.Scan).filter(db_models.Scan.threat_level == "high").count()
    total_users = db.query(db_models.User).count()
    
    return {
        "total_scans": total_scans,
        "high_threats": high_threats,
        "active_users": total_users,
        "system_status": "operational"
    }

@router.post("/generate-report")
def generate_report(report_data: Dict[str, Any], db: Session = Depends(get_db)):
    """Generate a report based on provided data."""
    try:
        path = reporting_service.generate_json_report(report_data, "osint_analysis")
        return {"message": "Report generated successfully", "path": path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
