from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models import db_models
from app.services.reporting import reporting_service
<<<<<<< HEAD
from app.services.export_service import export_service
from fastapi.responses import FileResponse
import os
=======
>>>>>>> d0f073da67d0618f343f8ec0c7a223c3526914d5
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
<<<<<<< HEAD

@router.get("/export/csv")
def export_scans_csv(db: Session = Depends(get_db)):
    """Export all scan history to CSV."""
    scans = db.query(db_models.Scan).all()
    data = []
    for s in scans:
        data.append({
            "id": s.id,
            "target": s.target,
            "scan_type": s.scan_type,
            "threat_level": s.threat_level,
            "threat_score": s.threat_score,
            "timestamp": s.timestamp
        })
    
    if not data:
        raise HTTPException(status_code=404, detail="No scans found to export")
    
    path = export_service.generate_csv(data, "scan_history")
    return FileResponse(path, filename=os.path.basename(path), media_type="text/csv")

@router.get("/export/pdf/{scan_id}")
def export_scan_pdf(scan_id: int, db: Session = Depends(get_db)):
    """Export a specific scan report to PDF."""
    scan = db.query(db_models.Scan).filter(db_models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    path = export_service.generate_pdf_report(scan.results, f"scan_report_{scan_id}")
    return FileResponse(path, filename=os.path.basename(path), media_type="application/pdf")
=======
>>>>>>> d0f073da67d0618f343f8ec0c7a223c3526914d5
