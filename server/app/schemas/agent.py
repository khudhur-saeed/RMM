from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class AgentBase(BaseModel):
    """Shared properties across agent schemas."""
    hostname: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Endpoint machine hostname",
    )
    os: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Operating system details and architecture (e.g. windows/amd64, linux/amd64)",
    )
    private_ip: Optional[str] = Field(
        default=None,
        max_length=45,
        description="Local private IPv4 or IPv6 network address",
    )


class AgentEnroll(AgentBase):
    """Inbound validation schema for initial agent registration."""
    token: str = Field(
        ...,
        min_length=16,
        description="Cryptographic enrollment token issued by the administrator",
    )


class AgentHeartbeat(BaseModel):
    """Inbound validation schema for periodic agent telemetry and keep-alive."""
    private_ip: Optional[str] = Field(
        default=None,
        max_length=45,
        description="Updated local private IP address if changed",
    )


class AgentRead(AgentBase):
    """Outbound serialization schema returned to API clients and dashboards."""
    id: UUID
    site_id: UUID
    public_ip: Optional[str] = None
    last_seen: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AgentEnrollResponse(AgentRead):
    """
    Outbound schema returned strictly once upon successful enrollment.
    Delivers the plaintext agent API key to the endpoint daemon.
    """
    api_key: str = Field(
        ...,
        description="Cryptographically generated raw API key. Only returned once during enrollment.",
    )