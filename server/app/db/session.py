import os
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

# Read credentials from environment or fallback to verified local defaults
POSTGRES_USER = os.getenv("POSTGRES_USER", "rmm_user")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "rmm_secure_dev_pass_2026")
POSTGRES_DB = os.getenv("POSTGRES_DB", "tactical_rmm")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5433")

DATABASE_URL = (
    f"postgresql+asyncpg://{POSTGRES_USER}:{POSTGRES_PASSWORD}"
    f"@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
)

# Asynchronous connection engine with connection pooling
engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

# Async session factory
async_session_factory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency generator for FastAPI endpoints.
    Yields an isolated AsyncSession and ensures proper closure.
    """
    async with async_session_factory() as session:
        try:
            yield session
        finally:
            await session.close()