"""Health check tests. DB and Redis are mocked, so no network is touched."""

from fastapi.testclient import TestClient
from pytest import MonkeyPatch

from app import main
from app.main import app


def test_healthz_ok_when_deps_up(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(main, "_check_db", _async_true)
    monkeypatch.setattr(main, "_check_redis", _async_true)
    with TestClient(app) as client:
        resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "database": True, "redis": True}


def test_healthz_degraded_when_db_down(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(main, "_check_db", _async_false)
    monkeypatch.setattr(main, "_check_redis", _async_true)
    with TestClient(app) as client:
        resp = client.get("/healthz")
    assert resp.status_code == 503
    assert resp.json() == {"status": "degraded", "database": False, "redis": True}


async def _async_true() -> bool:
    return True


async def _async_false() -> bool:
    return False
