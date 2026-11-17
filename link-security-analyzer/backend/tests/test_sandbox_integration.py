"""Integration tests for sandbox browser with local test server.

These tests require ALLOW_TEST_LOOPBACK=true in settings (tests only, never in compose).
"""

import asyncio
from typing import AsyncIterator
from urllib.parse import urlsplit

import pytest
from aiohttp import web

from app.config import Settings
from app.sandbox.browser import visit


# Test server fixtures
@pytest.fixture
async def test_server() -> AsyncIterator[str]:
    """Start a local test HTTP server on a random port."""
    app = web.Application()

    # Route 1: Benign page
    async def benign_page(request: web.Request) -> web.Response:
        return web.Response(
            text="""
            <!DOCTYPE html>
            <html>
            <head><title>Benign Test Page</title></head>
            <body>
                <h1>This is a test page</h1>
                <p>Nothing suspicious here.</p>
            </body>
            </html>
            """,
            content_type="text/html",
        )

    # Route 2: Page with delayed JS-rendered form
    async def delayed_form_page(request: web.Request) -> web.Response:
        return web.Response(
            text="""
            <!DOCTYPE html>
            <html>
            <head><title>JS Form Page</title></head>
            <body>
                <h1>Loading...</h1>
                <script>
                setTimeout(() => {
                    document.body.innerHTML = `
                        <h1>Login Form</h1>
                        <form>
                            <input type="text" name="username" placeholder="Username">
                            <input type="password" name="password" placeholder="Password">
                            <button type="submit">Submit</button>
                        </form>
                    `;
                }, 1000);
                </script>
            </body>
            </html>
            """,
            content_type="text/html",
        )

    # Route 3: Redirect chain (3 hops)
    async def redirect_1(request: web.Request) -> web.Response:
        base = str(request.url.origin())
        return web.Response(status=302, headers={"Location": f"{base}/redirect_2"})

    async def redirect_2(request: web.Request) -> web.Response:
        base = str(request.url.origin())
        return web.Response(status=302, headers={"Location": f"{base}/redirect_3"})

    async def redirect_3(request: web.Request) -> web.Response:
        base = str(request.url.origin())
        return web.Response(status=302, headers={"Location": f"{base}/final"})

    async def final(request: web.Request) -> web.Response:
        return web.Response(
            text="""
            <!DOCTYPE html>
            <html>
            <head><title>Final Page</title></head>
            <body><h1>You arrived!</h1></body>
            </html>
            """,
            content_type="text/html",
        )

    # Route 4: Page that triggers a download
    async def download_page(request: web.Request) -> web.Response:
        return web.Response(
            text="""
            <!DOCTYPE html>
            <html>
            <head><title>Download Test</title></head>
            <body>
                <h1>Download Test</h1>
                <a id="download" href="/file.zip" download>Download</a>
                <script>
                setTimeout(() => {
                    document.getElementById('download').click();
                }, 500);
                </script>
            </body>
            </html>
            """,
            content_type="text/html",
        )

    async def download_file(request: web.Request) -> web.Response:
        return web.Response(
            body=b"fake zip content",
            headers={
                "Content-Disposition": "attachment; filename=file.zip",
                "Content-Type": "application/zip",
            },
        )

    # Route 5: Slow page (>20s to load)
    async def slow_page(request: web.Request) -> web.Response:
        await asyncio.sleep(25)  # Exceed budget
        return web.Response(
            text="<html><body>Slow page</body></html>", content_type="text/html"
        )

    # Route 6: Page that redirects to metadata IP
    async def metadata_redirect(request: web.Request) -> web.Response:
        return web.Response(
            status=302, headers={"Location": "http://169.254.169.254/latest/meta-data/"}
        )

    # Route 7: Page with 200 requests (many images)
    async def many_requests_page(request: web.Request) -> web.Response:
        base = str(request.url.origin())
        img_tags = "\n".join(
            f'<img src="{base}/img/{i}.png" />' for i in range(200)
        )
        return web.Response(
            text=f"""
            <!DOCTYPE html>
            <html>
            <head><title>Many Requests</title></head>
            <body>
                <h1>Page with 200 images</h1>
                {img_tags}
            </body>
            </html>
            """,
            content_type="text/html",
        )

    async def fake_image(request: web.Request) -> web.Response:
        # 1x1 transparent PNG
        return web.Response(
            body=b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00"
            b"\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82",
            content_type="image/png",
        )

    # Add routes
    app.router.add_get("/benign", benign_page)
    app.router.add_get("/delayed_form", delayed_form_page)
    app.router.add_get("/redirect_1", redirect_1)
    app.router.add_get("/redirect_2", redirect_2)
    app.router.add_get("/redirect_3", redirect_3)
    app.router.add_get("/final", final)
    app.router.add_get("/download", download_page)
    app.router.add_get("/file.zip", download_file)
    app.router.add_get("/slow", slow_page)
    app.router.add_get("/metadata_redirect", metadata_redirect)
    app.router.add_get("/many_requests", many_requests_page)
    app.router.add_get("/img/{name}", fake_image)

    # Start server
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)  # Random port
    await site.start()

    port = site._server.sockets[0].getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"

    yield base_url

    # Cleanup
    await runner.cleanup()


@pytest.fixture
def test_settings() -> Settings:
    """Settings with ALLOW_TEST_LOOPBACK enabled."""
    return Settings(allow_test_loopback=True)


# Tests
@pytest.mark.asyncio
async def test_benign_page(test_server: str, test_settings: Settings) -> None:
    """Benign page returns title, screenshot, and no errors."""
    result = await visit(
        f"{test_server}/benign",
        budget_s=10.0,
        settings=test_settings,
        allow_test_loopback=True,
    )

    assert result.final_url == f"{test_server}/benign"
    assert result.title == "Benign Test Page"
    assert result.http_status == 200
    assert result.screenshot_png is not None
    assert len(result.screenshot_png) > 1000  # Non-trivial screenshot
    assert len(result.errors) == 0
    assert "127.0.0.1" in result.contacted_hosts


@pytest.mark.asyncio
async def test_delayed_js_form(test_server: str, test_settings: Settings) -> None:
    """JS-rendered form appears after settle time."""
    result = await visit(
        f"{test_server}/delayed_form",
        budget_s=10.0,
        settings=test_settings,
        allow_test_loopback=True,
    )

    assert result.title == "JS Form Page"
    assert result.rendered_html is not None
    # After 3s settle, form should be rendered
    assert "Login Form" in result.rendered_html
    assert 'type="password"' in result.rendered_html


@pytest.mark.asyncio
async def test_redirect_chain(test_server: str, test_settings: Settings) -> None:
    """Redirect chain is tracked correctly."""
    result = await visit(
        f"{test_server}/redirect_1",
        budget_s=10.0,
        settings=test_settings,
        allow_test_loopback=True,
    )

    assert result.final_url == f"{test_server}/final"
    assert result.title == "Final Page"
    assert len(result.redirect_chain) >= 3  # At least 3 hops
    assert any(hop.status in {301, 302, 303, 307, 308} for hop in result.redirect_chain)


@pytest.mark.asyncio
async def test_download_attempt(test_server: str, test_settings: Settings) -> None:
    """Download attempt is detected and blocked."""
    result = await visit(
        f"{test_server}/download",
        budget_s=10.0,
        settings=test_settings,
        allow_test_loopback=True,
    )

    assert result.download_attempted is True
    assert result.title == "Download Test"


@pytest.mark.asyncio
async def test_slow_page_timeout(test_server: str, test_settings: Settings) -> None:
    """Slow page (>20s) times out within budget (~16s)."""
    import time

    start = time.monotonic()
    result = await visit(
        f"{test_server}/slow",
        budget_s=15.0,
        settings=test_settings,
        allow_test_loopback=True,
    )
    elapsed = time.monotonic() - start

    # Should timeout before 20s (page sleep time)
    assert elapsed < 18  # Some buffer for overhead
    assert "timeout" in " ".join(result.errors).lower()


@pytest.mark.asyncio
async def test_metadata_redirect_blocked(
    test_server: str, test_settings: Settings
) -> None:
    """Redirect to metadata IP (169.254.169.254) is blocked by netguard."""
    result = await visit(
        f"{test_server}/metadata_redirect",
        budget_s=10.0,
        settings=test_settings,
        allow_test_loopback=True,
    )

    # The redirect to 169.254.169.254 should be blocked
    assert len(result.blocked_requests) > 0
    blocked_urls = " ".join(result.blocked_requests)
    assert "169.254.169.254" in blocked_urls


@pytest.mark.asyncio
async def test_many_requests_capped(test_server: str, test_settings: Settings) -> None:
    """Page with 200 requests is capped at 150."""
    result = await visit(
        f"{test_server}/many_requests",
        budget_s=15.0,
        settings=test_settings,
        allow_test_loopback=True,
    )

    # Should have blocked some requests due to 150 cap
    assert len(result.blocked_requests) > 0
    assert any("request_limit" in req for req in result.blocked_requests)


@pytest.mark.asyncio
async def test_contacted_hosts_tracking(
    test_server: str, test_settings: Settings
) -> None:
    """Contacted hosts are tracked correctly."""
    result = await visit(
        f"{test_server}/benign",
        budget_s=10.0,
        settings=test_settings,
        allow_test_loopback=True,
    )

    assert len(result.contacted_hosts) > 0
    assert "127.0.0.1" in result.contacted_hosts
    # Third-party ratio should be 0 (all requests to same host)
    assert result.third_party_ratio == 0.0
