from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class OrganizationBase(BaseModel):
    """Shared properties across organization schemas."""
    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Unique business name of the tenant organization",
    )


class OrganizationCreate(OrganizationBase):
    """Inbound validation schema for creating a new Organization."""
    pass


class OrganizationRead(OrganizationBase):
    """Outbound serialization schema returned to API clients."""
    id: UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)