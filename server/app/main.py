import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from sqlalchemy import text

from app.api.v1.router import api_v1_router
from app.core.config import settings
from app.core.crypto import get_signing_keypair
from app.db.session import engine
from app.services.watchdog import run_agent_watchdog


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Manages application lifespan states:
    1. Verifies PostgreSQL connectivity.
    2. Spawns the background agent heartbeat watchdog task.
    3. Gracefully cancels and drains background workers before disposing database connection pools.
    """
    # 1. Startup phase: Fail-fast database socket verification & Ed25519 key bootstrap
    async with engine.connect() as connection:
        await connection.execute(text("SELECT 1"))
    get_signing_keypair()

    # 2. Spawn agent watchdog background worker
    watchdog_task = asyncio.create_task(run_agent_watchdog(interval_seconds=30, threshold_seconds=90))

    yield

    # 3. Shutdown phase: Signal and cancel the background watchdog worker safely
    watchdog_task.cancel()
    await asyncio.gather(watchdog_task, return_exceptions=True)

    # 4. Drain and close physical database connection pool
    await engine.dispose()


def create_application() -> FastAPI:
    """
    Application factory pattern.
    Configures API metadata, routers, and lifespan management.
    """
    application = FastAPI(
        title=settings.PROJECT_NAME,
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        docs_url=f"{settings.API_V1_STR}/docs",
        redoc_url=f"{settings.API_V1_STR}/redoc",
        lifespan=lifespan,
    )

    # Attach versioned API router aggregation
    application.include_router(
        api_v1_router,
        prefix=settings.API_V1_STR,
    )

    return application


app = create_application()