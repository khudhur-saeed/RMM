from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class SoftwareBase(BaseModel):
    """Normalized software metadata reported by an endpoint agent."""
    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Application or package display name",
    )
    version: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Installed package version string",
    )
    publisher: Optional[str] = Field(
        default=None,
        max_length=255,
        description="Software vendor, publisher, or package maintainer",
    )
    install_date: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Installation date string if reported by the OS",
    )


class SoftwareRead(SoftwareBase):
    """Outbound serialization schema for persisted endpoint software inventory."""
    id: UUID
    agent_id: UUID
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
