from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, FrozenSet, Optional
import uuid

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.organization import Organization
    from app.models.site import Site


class Role(str, Enum):
    """
    Canonical Role-Based Access Control (RBAC) roles for the Tactical RMM control plane.
    - SuperAdmin: Full unrestricted multi-tenant and cryptographic administration.
    - SiteTechnician: Operational administration and C2 task/terminal dispatch scoped to assigned site(s).
    - Auditor: Strictly read-only compliance, inventory, telemetry, and signature verification access.
    """

    SUPER_ADMIN = "SuperAdmin"
    SITE_TECHNICIAN = "SiteTechnician"
    AUDITOR = "Auditor"


class Permission(str, Enum):
    """Granular control-plane and C2 WebSocket permissions mapped to RBAC roles."""

    # Tenant Organization boundaries
    ORG_READ = "organizations:read"
    ORG_WRITE = "organizations:write"

    # Site boundaries
    SITE_READ = "sites:read"
    SITE_WRITE = "sites:write"

    # Agent Enrollment Tokens
    TOKEN_READ = "tokens:read"
    TOKEN_WRITE = "tokens:write"

    # Endpoint Agents, Software Inventory & Telemetry
    AGENT_READ = "agents:read"
    AGENT_WRITE = "agents:write"
    AGENT_DISPATCH = "agents:dispatch"

    # Script Keystore & Parameterized Execution
    SCRIPT_READ = "scripts:read"
    SCRIPT_WRITE = "scripts:write"
    SCRIPT_EXECUTE = "scripts:execute"

    # Ed25519 Cryptographic Code-Signing Keys
    KEY_READ = "keys:read"
    KEY_VERIFY = "keys:verify"
    KEY_SIGN = "keys:sign"
    KEY_ROTATE = "keys:rotate"

    # Real-Time C2 WebSocket Tunnels
    WS_CONNECT = "ws:connect"
    WS_DISPATCH = "ws:dispatch"

    # RBAC Operator User Management
    USER_READ = "users:read"
    USER_WRITE = "users:write"

    # Immutable Security Audit Logs
    AUDIT_READ = "audit:read"


ROLE_PERMISSIONS: dict[Role, FrozenSet[Permission]] = {
    Role.SUPER_ADMIN: frozenset(Permission),
    Role.SITE_TECHNICIAN: frozenset(
        {
            Permission.ORG_READ,
            Permission.SITE_READ,
            Permission.TOKEN_READ,
            Permission.TOKEN_WRITE,
            Permission.AGENT_READ,
            Permission.AGENT_WRITE,
            Permission.AGENT_DISPATCH,
            Permission.SCRIPT_READ,
            Permission.SCRIPT_EXECUTE,
            Permission.KEY_READ,
            Permission.KEY_VERIFY,
            Permission.KEY_SIGN,
            Permission.WS_CONNECT,
            Permission.WS_DISPATCH,
        }
    ),
    Role.AUDITOR: frozenset(
        {
            Permission.ORG_READ,
            Permission.SITE_READ,
            Permission.TOKEN_READ,
            Permission.AGENT_READ,
            Permission.SCRIPT_READ,
            Permission.KEY_READ,
            Permission.KEY_VERIFY,
            Permission.USER_READ,
            Permission.AUDIT_READ,
            Permission.WS_CONNECT,
        }
    ),
}


ROLE_DESCRIPTIONS: dict[Role, str] = {
    Role.SUPER_ADMIN: (
        "Full global administrative control across all tenant organizations, sites, "
        "script keystores, Ed25519 signing keys, RBAC operators, and C2 WebSocket tunnels."
    ),
    Role.SITE_TECHNICIAN: (
        "Operational technician privileges for viewing site inventory/telemetry, "
        "issuing enrollment tokens, rendering parameterized scripts, and dispatching "
        "signed C2 tasks and interactive WebSocket terminal commands within assigned sites."
    ),
    Role.AUDITOR: (
        "Read-only security and compliance auditing across organizations, sites, agents, "
        "software catalogs, telemetry snapshots, scripts, and cryptographic signature verification. "
        "Strictly prohibited from mutating state or dispatching C2 commands."
    ),
}


class User(Base):
    """
    Represents a human operator or service account governed by Role-Based Access Control (RBAC).
    """

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "role IN ('SuperAdmin', 'SiteTechnician', 'Auditor')",
            name="ck_users_valid_role",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    username: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )
    email: Mapped[Optional[str]] = mapped_column(
        String(255),
        unique=True,
        nullable=True,
        index=True,
    )
    role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=Role.AUDITOR.value,
        index=True,
    )
    api_token_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
    )
    org_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    site_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sites.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    organization: Mapped[Optional["Organization"]] = relationship(
        "Organization",
        lazy="selectin",
    )
    site: Mapped[Optional["Site"]] = relationship(
        "Site",
        lazy="selectin",
    )

    @property
    def role_enum(self) -> Role:
        """Returns the typed Role enum for this user."""
        return Role(self.role)

    @property
    def permissions(self) -> FrozenSet[Permission]:
        """Returns the immutable permission set granted to this user's role."""
        if not self.is_active:
            return frozenset()
        return ROLE_PERMISSIONS.get(self.role_enum, frozenset())

    def has_permission(self, permission: Permission | str) -> bool:
        """Checks whether this user holds the specified permission."""
        if not self.is_active:
            return False
        perm = Permission(permission) if isinstance(permission, str) else permission
        return perm in self.permissions
