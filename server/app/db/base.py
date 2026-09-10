from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase


class Base(AsyncAttrs, DeclarativeBase):
    """
    Base declarative class for all SQLAlchemy 2.0 models in Tactical RMM.
    Provides async attribute access and shared metadata registration.
    """
    pass


