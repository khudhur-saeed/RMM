from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

class SiteBase(BaseModel):
    """Shared properties across site schemas."""
    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Physical branch or logical subnet site name",
    )

class SiteCreate(SiteBase):
    """Inbound validation schema for creating a new Site."""
    org_id: UUID = Field(
        ...,
        description="Foreign key identifier of the parent tenant organization",
    )

class SiteRead(SiteBase):
    """Outbound serialization schema returned to API clients."""
    id: UUID
    org_id: UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)