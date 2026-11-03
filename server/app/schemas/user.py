from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.user import Permission, Role


class UserCreate(BaseModel):
    """Schema for creating a new RBAC operator user account."""

    username: str = Field(
        ...,
        min_length=2,
        max_length=100,
        description="Unique operator username",
    )
    email: Optional[str] = Field(
        default=None,
        max_length=255,
        description="Optional operator email address",
    )
    role: Role = Field(
        default=Role.AUDITOR,
        description="Assigned RBAC role: SuperAdmin, SiteTechnician, or Auditor",
    )
    org_id: Optional[UUID] = Field(
        default=None,
        description="Optional tenant organization scope UUID",
    )
    site_id: Optional[UUID] = Field(
        default=None,
        description="Optional site scope UUID (for SiteTechnician or site-scoped Auditor)",
    )
    is_active: bool = Field(
        default=True,
        description="Whether the operator account is active",
    )

    @field_validator("username")
    @classmethod
    def normalize_username(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Username cannot be empty or whitespace only.")
        return cleaned

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        cleaned = v.strip().lower()
        return cleaned or None


class UserUpdate(BaseModel):
    """Schema for updating an existing RBAC operator account."""

    email: Optional[str] = Field(default=None, max_length=255)
    role: Optional[Role] = Field(default=None)
    org_id: Optional[UUID] = Field(default=None)
    site_id: Optional[UUID] = Field(default=None)
    is_active: Optional[bool] = Field(default=None)


class UserRead(BaseModel):
    """Public representation of an RBAC user (excludes raw token and token hash)."""

    id: UUID
    username: str
    email: Optional[str] = None
    role: Role
    org_id: Optional[UUID] = None
    site_id: Optional[UUID] = None
    is_active: bool
    permissions: List[Permission] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserCreateResponse(UserRead):
    """
    Returned only once upon user creation or token rotation,
    exposing the plaintext bearer API token.
    """

    api_token: str = Field(
        ...,
        description="One-time plaintext bearer API token for the created operator",
    )


class PrincipalRead(BaseModel):
    """Schema representing the currently authenticated RBAC principal."""

    id: Optional[UUID] = None
    username: str
    role: Role
    permissions: List[Permission]
    org_id: Optional[UUID] = None
    site_id: Optional[UUID] = None
    is_active: bool = True
    is_bootstrap: bool = False


class RoleMetadataRead(BaseModel):
    """Schema describing an RBAC role and its granted permissions."""

    role: Role
    description: str
    permissions: List[Permission]
