import uuid
from datetime import datetime
from typing import List, TYPE_CHECKING, Optional

from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import String, ForeignKey, DateTime, func
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


if TYPE_CHECKING:
    from app.models.site import Site
    from app.models.software import InstalledSoftware


class Agent(Base):
    """
    Represents a monitored endpoint (workstation or server)
    running the Tactical RMM agent daemon.
    """
    __tablename__ = "agents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sites.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    hostname: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    os: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    api_key_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
    )
    public_ip: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )
    private_ip: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )
    last_seen: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    site: Mapped["Site"] = relationship(
        "Site",
        back_populates="agents",
    )
    installed_software: Mapped[List["InstalledSoftware"]] = relationship(
        "InstalledSoftware",
        back_populates="agent",
        cascade="all, delete-orphan",
    )