import uuid 
from sqlalchemy.orm import Mapped, mapped_column, relationship 
from sqlalchemy import String, DateTime, func
from datetime import datetime
from typing import List, TYPE_CHECKING 
from sqlalchemy.dialects.postgresql import UUID
from app.db.base import Base 


if TYPE_CHECKING:
    from app.models.site import Site

class Organization(Base):
    """
    Represents the top-level tenant (MSP or enterprise account).
    Enforces strict data isolation boundaries across all sites and agents.
    """
    __tablename__ ="organizations"

    id : Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    name : Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )
    created_at : Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    sites : Mapped[List["Site"]] = relationship(
        "Site",
        back_populates="organization",
        cascade="all, delete-orphan"
    )