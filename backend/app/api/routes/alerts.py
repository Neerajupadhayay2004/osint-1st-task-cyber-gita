from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models import db_models
from typing import List

router = APIRouter()

@router.get("/", response_model=None)
def get_alerts(db: Session = Depends(get_db)):
    """Get all alerts."""
    return db.query(db_models.Alert).order_by(db_models.Alert.timestamp.desc()).all()

@router.post("/read/{alert_id}")
def mark_alert_as_read(alert_id: int, db: Session = Depends(get_db)):
    """Mark an alert as read."""
    alert = db.query(db_models.Alert).filter(db_models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_read = True
    db.commit()
    return {"message": "Alert marked as read"}

@router.post("/create")
def create_alert(alert_data: dict, db: Session = Depends(get_db)):
    """Internal endpoint to create an alert."""
    new_alert = db_models.Alert(
        title=alert_data["title"],
        message=alert_data["message"],
        severity=alert_data.get("severity", "info")
    )
    db.add(new_alert)
    db.commit()
    db.refresh(new_alert)
    return new_alert
