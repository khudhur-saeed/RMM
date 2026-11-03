from datetime import datetime
from typing import Any, Dict, Optional
import uuid

from sqlalchemy import DateTime, Integer, String, Text, event, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditLogImmutabilityError(PermissionError):
    """
    Raised when any code path attempts to UPDATE or DELETE an immutable AuditLog record.
    """


class AuditLog(Base):
    """
    Append-only, immutable security audit log record for control-plane and C2 operations.
    Records the executing operator (admin_id), target endpoint agent (target_agent_id),
    dispatched command/payload text (command_text), and SHA-256 output digest (output_hash).

    Immutability is enforced at both the SQLAlchemy ORM layer (before_update / before_delete
    event hooks) and the PostgreSQL storage layer (BEFORE UPDATE OR DELETE row trigger).
    """

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    admin_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
    )
    admin_username: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    admin_role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    target_agent_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
    )
    task_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
    )
    action: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )
    method: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )
    path: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    command_text: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
    )
    output_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    status_code: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=200,
    )
    client_ip: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    @property
    def target_agent(self) -> Optional[uuid.UUID]:
        """Alias property returning target_agent_id for schema/caller convenience."""
        return self.target_agent_id


@event.listens_for(AuditLog, "before_update")
def _prevent_audit_log_update(mapper, connection, target) -> None:
    raise AuditLogImmutabilityError(
        "AuditLog records are append-only and immutable; UPDATE operations are strictly prohibited."
    )


@event.listens_for(AuditLog, "before_delete")
def _prevent_audit_log_delete(mapper, connection, target) -> None:
    raise AuditLogImmutabilityError(
        "AuditLog records are append-only and immutable; DELETE operations are strictly prohibited."
    )
