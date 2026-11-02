import uuid
from datetime import datetime
from typing import List, TYPE_CHECKING

from sqlalchemy import String, ForeignKey, DateTime, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.agent import Agent
    from app.models.organization import Organization
    from app.models.token import EnrollmentToken


class Site(Base):
    """
    Represents a physical branch, network subnet, or customer site
    belonging to an Organization.
    """
    __tablename__ = "sites"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_sites_org_id_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    organization: Mapped["Organization"] = relationship(
        "Organization",
        back_populates="sites",
    )
    agents: Mapped[List["Agent"]] = relationship(
        "Agent",
        back_populates="site",
        cascade="all, delete-orphan",
    )
    enrollment_tokens: Mapped[List["EnrollmentToken"]] = relationship(
        "EnrollmentToken",
        back_populates="site",
        cascade="all, delete-orphan",
    )