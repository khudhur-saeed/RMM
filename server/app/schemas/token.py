from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class EnrollmentTokenBase(BaseModel):
    """Shared properties across enrollment token schemas."""
    site_id: UUID = Field(
        ...,
        description="Target site identifier the agent will be assigned to upon enrollment",
    )


class EnrollmentTokenCreate(EnrollmentTokenBase):
    """
    Inbound validation schema for issuing a new token.
    Defines the token validity lifespan in hours.
    """
    valid_hours: int = Field(
        default=24,
        ge=1,
        le=720,
        description="Token lifespan in hours (between 1 hour and 30 days)",
    )


class EnrollmentTokenRead(EnrollmentTokenBase):
    """Outbound serialization schema returned strictly once upon token generation."""
    id: UUID
    token: str
    is_used: bool = False
    expires_at: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EnrollmentTokenPublic(EnrollmentTokenBase):
    """Redacted outbound schema for listing enrollment tokens without exposing raw secrets."""
    id: UUID
    is_used: bool
    expires_at: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)