from pydantic import BaseModel
from typing import List, Optional

class ThreatInfo(BaseModel):
    ip: str
    is_malicious: bool
    threat_score: float
    provider_results: dict
    detected_threats: List[str]
    last_scan: str
