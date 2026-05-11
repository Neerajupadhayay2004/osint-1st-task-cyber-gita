from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class ScanHistory(BaseModel):
    id: int
    ip: str
    scan_date: datetime
    result_summary: str
    user_id: Optional[int] = None

