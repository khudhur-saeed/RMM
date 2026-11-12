from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AuditLogRead(BaseModel):
    """
    Read-only representation of an immutable security audit log entry.
    Includes both `target_agent_id` and `target_agent` fields for convenience.
    """

    id: UUID
    admin_id: UUID
    admin_username: str
    admin_role: str
    org_id: Optional[UUID] = None
    site_id: Optional[UUID] = None
    target_agent_id: Optional[UUID] = None
    target_agent: Optional[UUID] = None
    task_id: Optional[UUID] = None
    action: str
    method: str
    path: str
    command_text: str
    output_hash: str
    status_code: int
    client_ip: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
