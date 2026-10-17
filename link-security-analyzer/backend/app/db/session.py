"""Database engines and sessions.

Two doors to the same filing cabinet: an async door for the FastAPI web
server (many visitors at once) and a sync door for the Celery background
worker (one steady clerk). Engines are built lazily so importing this
module never touches the network.
"""

from collections.abc import AsyncIterator, Iterator
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings


@lru_cache(maxsize=1)
def get_async_engine() -> AsyncEngine:
    """Build (once) the async engine used by FastAPI requests."""
    settings = get_settings()
    return create_async_engine(settings.database_url, pool_pre_ping=True)


@lru_cache(maxsize=1)
def get_sync_engine() -> Engine:
    """Build (once) the sync engine used by the Celery worker and Alembic."""
    settings = get_settings()
    return create_engine(settings.sync_database_url, pool_pre_ping=True)


def _async_session_factory() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(bind=get_async_engine(), expire_on_commit=False)


def _sync_session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_sync_engine(), expire_on_commit=False)


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: yield one async session per request."""
    session_factory = _async_session_factory()
    async with session_factory() as session:
        yield session


def get_sync_session() -> Iterator[Session]:
    """Yield one sync session for the Celery worker."""
    session_factory = _sync_session_factory()
    with session_factory() as session:
        yield session
