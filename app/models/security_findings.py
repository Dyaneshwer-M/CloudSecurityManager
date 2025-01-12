from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class SecurityFinding(BaseModel):
    resource_id: str
    severity: str
    finding_type: str
    description: str
    remediation: str
    created_at: datetime = datetime.utcnow()
    metadata: Optional[dict] = None
