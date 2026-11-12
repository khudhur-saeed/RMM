from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ws_manager import ws_manager
from app.db.session import get_db

router = APIRouter()


@router.get("/health", status_code=status.HTTP_200_OK)
async def check_health(db: AsyncSession = Depends(get_db)):
    """
    Production health check endpoint verifying the API control plane,
    asynchronous PostgreSQL connectivity, and Redis state store liveness.
    """
    try:
        await db.execute(text("SELECT 1"))
        redis_ok = await ws_manager.redis_client.ping()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Dependency health check failed: {exc}",
        )

    return {
        "status": "healthy",
        "database": "connected",
        "redis": "connected" if redis_ok else "degraded",
    }
