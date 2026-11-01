from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class AlertSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class AlertCategory(str, Enum):
    CPU_SPIKE = "CPU_SPIKE"
    SERVICE_STOPPED = "SERVICE_STOPPED"
    BRUTE_FORCE = "BRUTE_FORCE"


class AlertEvent(BaseModel):
    agent_id: UUID
    category: AlertCategory
    severity: AlertSeverity
    title: str
    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class HardwareMetricsPayload(BaseModel):
    cpu_percent: float = Field(..., ge=0.0, le=100.0)
    memory_percent: float = Field(..., ge=0.0, le=100.0)


class ServiceStatusEntry(BaseModel):
    name: str
    status: str  # "running", "stopped", etc.
    is_critical: bool = False


class ServiceStatusPayload(BaseModel):
    services: List[ServiceStatusEntry]


class AuthEventPayload(BaseModel):
    event_type: str  # "SSH_LOGIN_FAILED", "SSH_LOGIN_SUCCESS", "SUDO_FAILED"
    username: str
    source_ip: Optional[str] = None
    timestamp: Optional[datetime] = None
