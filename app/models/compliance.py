

from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class ComplianceCheck(BaseModel):
    check_id: str
    framework: str
    category: str
    description: str
    severity: str
    result: str
    resource_id: str
    details: Optional[dict] = None
    checked_at: datetime = datetime.utcnow()