from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, Boolean
from app.core.database import Base
from datetime import datetime

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, index=True)
    scan_type = Column(String)  # ip, domain, email
    results = Column(JSON)
    threat_level = Column(String)
    threat_score = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)

class ThreatIntelligence(Base):
    __tablename__ = "threat_intel"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String)
    data = Column(JSON)
    timestamp = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    message = Column(String)
    severity = Column(String)  # info, warning, critical
    is_read = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
