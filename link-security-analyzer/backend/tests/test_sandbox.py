"""Sandbox request guard and DOM audit tests; no external network is used."""

import inspect
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.config import Settings
from app.core.models import Indicator
from app.core.netguard import BlockedTargetError
from app.core.sandbox import (
    RequestGuard,
    _redirect_indicators,
    audit_dom,
    scan_page,
)

_FIXTURE = Path(__file__).parent / "fixtures" / "sandbox_login.html"


class _Request:
    def __init__(
        self,
        url: str,
        *,
        resource_type: str = "document",
        navigation: bool = True,
    ) -> None:
        self.url = url
        self.resource_type = resource_type
        self._navigation = navigation

    def is_navigation_request(self) -> bool:
        return self._navigation


class _Route:
    def __init__(self) -> None:
        self.aborted: str | None = None
        self.continued = False

    async def abort(self, reason: str) -> None:
        self.aborted = reason

    async def continue_(self) -> None:
        self.continued = True


class _WebSocketRoute:
    url = "ws://127.0.0.1/private"

    def __init__(self) -> None:
        self.closed: tuple[int | None, str | None] | None = None

    async def close(
        self, *, code: int | None = None, reason: str | None = None
    ) -> None:
        self.closed = (code, reason)


def test_dom_audit_finds_sensitive_forms_hidden_iframe_and_refresh() -> None:
    html = _FIXTURE.read_text(encoding="utf-8")
    indicators = audit_dom(
        html,
        "https://login.example/",
        domain_age_days=12,
    )
    codes = {item.code for item in indicators}
    assert {
        "FORM_POSTS_TO_DIFFERENT_DOMAIN",
        "FORM_POSTS_OVER_HTTP",
        "PASSWORD_FIELD_PRESENT",
        "SENSITIVE_FIELD_REQUESTED",
        "NEW_DOMAIN_LOGIN_FORM",
        "HIDDEN_IFRAME",
        "META_REFRESH_REDIRECT",
    } <= codes
    sensitive = next(
        item for item in indicators if item.code == "SENSITIVE_FIELD_REQUESTED"
    )
    assert sensitive.evidence["field_types"] == "otp"


def test_dom_audit_does_not_flag_old_domain_login_as_new() -> None:
    indicators = audit_dom(
        '<form><input type="password"></form>',
        "https://account.example/",
        domain_age_days=60,
    )
    assert "PASSWORD_FIELD_PRESENT" in {item.code for item in indicators}
    assert "NEW_DOMAIN_LOGIN_FORM" not in {item.code for item in indicators}


@pytest.mark.parametrize("scheme", ["file", "data", "javascript"])
async def test_request_guard_aborts_non_http_schemes(scheme: str) -> None:
    route = _Route()
    request = _Request(f"{scheme}://example.test/path")
    guard = RequestGuard([], max_navigations=5)
    await guard.handle(route, request)
    assert route.aborted == "blockedbyclient"
    assert guard.indicators[0].code == "SANDBOX_BLOCKED_REQUEST"
    assert guard.indicators[0].evidence["reason"] == "UNSUPPORTED_SCHEME"


async def test_request_guard_aborts_netguard_denied_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def deny_target(url: str, **kwargs: object) -> None:
        raise BlockedTargetError("NON_PUBLIC_ADDRESS", "blocked test target")

    monkeypatch.setattr("app.core.sandbox.assert_public_target", deny_target)
    route = _Route()
    guard = RequestGuard([], max_navigations=5)
    await guard.handle(route, _Request("https://private.example/path?query=omit"))
    assert route.aborted == "blockedbyclient"
    assert guard.indicators[0].evidence == {
        "host": "private.example",
        "reason": "NON_PUBLIC_ADDRESS",
    }


async def test_websocket_guard_checks_host_and_closes_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def deny_target(url: str, **kwargs: object) -> None:
        assert url.startswith("http://127.0.0.1")
        raise BlockedTargetError("NON_PUBLIC_ADDRESS", "blocked test target")

    monkeypatch.setattr("app.core.sandbox.assert_public_target", deny_target)
    socket = _WebSocketRoute()
    guard = RequestGuard([], max_navigations=5)
    await guard.handle_websocket(socket)  # type: ignore[arg-type]
    assert socket.closed == (1008, "WebSocket connections are disabled.")
    assert guard.indicators[0].evidence["reason"] == "NON_PUBLIC_ADDRESS"


async def test_request_guard_aborts_media_and_navigation_over_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def allow_target(url: str, **kwargs: object) -> object:
        return object()

    monkeypatch.setattr("app.core.sandbox.assert_public_target", allow_target)
    guard = RequestGuard([], max_navigations=1)
    media_route = _Route()
    await guard.handle(
        media_route,
        _Request(
            "https://public.example/video",
            resource_type="media",
            navigation=False,
        ),
    )
    first_route = _Route()
    await guard.handle(first_route, _Request("https://public.example/one"))
    second_route = _Route()
    await guard.handle(second_route, _Request("https://public.example/two"))
    assert media_route.aborted == "blockedbyclient"
    assert first_route.continued
    assert second_route.aborted == "blockedbyclient"
    assert [item.evidence["reason"] for item in guard.indicators] == [
        "DISALLOWED_RESOURCE_TYPE",
        "NAVIGATION_LIMIT",
    ]


def test_redirect_indicators_store_hosts_without_url_paths() -> None:
    indicators: list[Indicator] = []
    hosts = [
        "a.example",
        "b.example",
        "c.example",
        "d.example",
        "e.example",
    ]
    _redirect_indicators(hosts, indicators, http_redirect_count=4)
    assert {item.code for item in indicators} == {
        "REDIRECT_CHAIN_LONG",
        "REDIRECT_CROSS_DOMAIN",
    }
    assert all("/" not in str(item.evidence) for item in indicators)


async def test_local_target_requires_explicit_test_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    async def deny_target(url: str, **kwargs: object) -> None:
        calls.append(url)
        raise BlockedTargetError("DENIED_HOSTNAME", "loopback disabled")

    monkeypatch.setattr("app.core.sandbox.assert_public_target", deny_target)
    default_result = await scan_page(
        "http://127.0.0.1:8000/", settings=Settings(_env_file=None)
    )
    assert default_result.status == "FLAGGED"
    assert calls == ["http://127.0.0.1:8000/"]
    assert (
        inspect.signature(scan_page).parameters["_allow_local_test_targets"].default
        is False
    )


class _LocalHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = self.path.split("?", maxsplit=1)[0]
        if path == "/start":
            self.send_response(302)
            self.send_header("Location", "/middle")
            self.end_headers()
            return
        if path == "/middle":
            self.send_response(302)
            self.send_header("Location", "/final?session=placeholder")
            self.end_headers()
            return
        body = (
            b'<form method="post" action="https://collector.example/submit">'
            b'<input type="password" name="password"></form>'
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


@pytest.fixture
def local_redirect_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LocalHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/start?session=placeholder"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.integration
async def test_browser_integration_local_redirect_and_external_form(
    local_redirect_server: str,
) -> None:
    result = await scan_page(
        local_redirect_server,
        settings=Settings(_env_file=None),
        _allow_local_test_targets=True,
    )
    codes = {item.code for item in result.indicators}
    assert "FORM_POSTS_TO_DIFFERENT_DOMAIN" in codes
    redirect_hosts = result.features["redirect_chain_hosts"].split(" -> ")
    assert len(redirect_hosts) >= 3
    assert set(redirect_hosts) == {"127.0.0.1"}
    assert result.features["final_url"].endswith("/final")
    assert "?" not in result.features["final_url"]
    assert "placeholder" not in str(result.features)
