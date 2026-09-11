from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from sqlalchemy import text

from app.api.v1.router import api_v1_router
from app.core.config import settings
from app.db.session import engine


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Manages application lifespan states.
    Verifies database connectivity on startup and purges connection pools on shutdown.
    """
    async with engine.connect() as connection:
        await connection.execute(text("SELECT 1"))

    yield

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