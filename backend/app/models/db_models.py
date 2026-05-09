from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, JSON, Float
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", back_populates="owner")
    alerts = relationship("Alert", back_populates="user")

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, index=True)  # IP, Domain, Hash, etc.
    scan_type = Column(String)  # 'virustotal', 'shodan', 'abuseipdb', 'combined'
    results = Column(JSON)
    threat_level = Column(String)  # 'low', 'medium', 'high', 'critical'
    threat_score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User", back_populates="scans")

class ThreatIntelligence(Base):
    __tablename__ = "threat_intel"

    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String, index=True, unique=True)
    type = Column(String)  # 'ipv4', 'domain', 'url', 'hash'
    source = Column(String)  # 'MalwareBazaar', 'URLHaus', etc.
    description = Column(String)
    severity = Column(String)
    last_seen = Column(DateTime, default=datetime.utcnow)
    raw_data = Column(JSON)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    message = Column(String)
    severity = Column(String)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"))

    user = relationship("User", back_populates="alerts")
