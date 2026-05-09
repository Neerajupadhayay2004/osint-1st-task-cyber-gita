from pydantic import BaseModel, EmailStr
from typing import List, Optional, Any
from datetime import datetime

# Auth Schemas
class UserBase(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None
    is_active: Optional[bool] = True

class UserCreate(UserBase):
    password: str

class UserUpdate(UserBase):
    password: Optional[str] = None

class User(UserBase):
    id: int
    created_at: datetime
    is_superuser: bool

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

# OSINT Schemas
class ScanBase(BaseModel):
    target: str
    scan_type: str

class ScanCreate(ScanBase):
    pass

class ScanResult(ScanBase):
    id: int
    results: Any
    threat_level: str
    threat_score: float
    created_at: datetime

    class Config:
        from_attributes = True

# Threat Intel Schemas
class ThreatIntelBase(BaseModel):
    indicator: str
    type: str
    source: str
    severity: str

class ThreatIntel(ThreatIntelBase):
    id: int
    description: Optional[str]
    last_seen: datetime

    class Config:
        from_attributes = True

# Alert Schemas
class AlertBase(BaseModel):
    title: str
    message: str
    severity: str

class Alert(AlertBase):
    id: int
    is_read: bool
    created_at: datetime

    class Config:
        from_attributes = True
