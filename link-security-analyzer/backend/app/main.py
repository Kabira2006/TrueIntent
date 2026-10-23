"""FastAPI entrypoint: CORS plus a health check for the container stack."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import redis.asyncio as redis
from fastapi import FastAPI, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.api.v1.endpoints import router as scan_router
from app.config import get_settings
from app.db.session import get_async_engine

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup/shutdown hook. Nothing heavy here yet."""
    logger.info("link-security-analyzer starting")
    yield
    await get_async_engine().dispose()
    logger.info("link-security-analyzer stopped")


settings = get_settings()

app = FastAPI(
    title="TrueIntent Link Security Analyzer", version="0.1.0", lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(scan_router, prefix="/api/v1")


async def _check_db() -> bool:
    try:
        async with get_async_engine().connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001 - health check must never raise
        logger.warning("db health check failed")
        return False


async def _check_redis() -> bool:
    client = redis.from_url(settings.redis_url)
    try:
        await client.ping()
        return True
    except Exception:  # noqa: BLE001 - health check must never raise
        logger.warning("redis health check failed")
        return False
    finally:
        await client.aclose()


@app.get("/healthz")
async def healthz(response: Response) -> dict[str, object]:
    """Return 200 only when both Postgres and Redis answer."""
    db_ok = await _check_db()
    redis_ok = await _check_redis()
    healthy = db_ok and redis_ok
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ok" if healthy else "degraded",
        "database": db_ok,
        "redis": redis_ok,
    }
