from fastapi import APIRouter, Depends, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db

router = APIRouter()


@router.get("/health", status_code=status.HTTP_200_OK)
async def check_health(db: AsyncSession = Depends(get_db)):
    """
    Health check endpoint verifying the API control plane
    and real-time asynchronous PostgreSQL connectivity.
    """
    await db.execute(text("SELECT 1"))
    return {
        "status": "healthy",
        "database": "connected",
    }