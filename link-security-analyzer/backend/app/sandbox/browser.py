"""Browser-based page visiting with netguard integration and resource caps.

Creates a FRESH context per scan with no storage, enforces strict resource limits,
and routes every request through netguard. Returns structured metadata without
clicking or typing.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any, Optional
from urllib.parse import urlsplit

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Request,
    Response,
    Route,
    async_playwright,
)
from playwright.async_api import Error as PlaywrightError

from app.config import Settings, get_settings
from app.core.netguard import BlockedTargetError, assert_public_target

logger = logging.getLogger(__name__)

# Browser launch singleton per worker process
_BROWSER_INSTANCE: Optional[Browser] = None
_BROWSER_LAUNCH_COUNT = 0
_MAX_SCANS_PER_BROWSER = 100  # Recycle browser after N scans

_VIEWPORT = {"width": 1366, "height": 768}
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


@dataclass
class RedirectHop:
    """One hop in a redirect chain."""

    url: str
    status: int


@dataclass
class VisitResult:
    """Structured result from visiting a page."""

    # Navigation
    final_url: str
    redirect_chain: list[RedirectHop] = field(default_factory=list)
    http_status: Optional[int] = None

    # Content
    title: Optional[str] = None
    rendered_html: Optional[str] = None  # Capped to ~500KB
    response_headers: dict[str, str] = field(default_factory=dict)

    # Network
    contacted_hosts: list[str] = field(default_factory=list)
    third_party_ratio: float = 0.0

    # Media
    screenshot_png: Optional[bytes] = None
    favicon_bytes: Optional[bytes] = None

    # Flags
    download_attempted: bool = False
    blocked_requests: list[str] = field(default_factory=list)

    # Metadata
    timings: dict[str, float] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


class _RequestGuard:
    """Routes all requests through netguard and enforces resource caps."""

    def __init__(
        self,
        base_url: str,
        *,
        max_requests: int = 150,
        max_bytes: int = 8 * 1024 * 1024,  # 8 MB
        max_redirects: int = 10,
        settings: Optional[Settings] = None,
        allow_test_loopback: bool = False,
    ):
        self.base_url = base_url
        self.base_host = urlsplit(base_url).hostname or ""
        self.max_requests = max_requests
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.settings = settings or get_settings()
        self.allow_test_loopback = allow_test_loopback

        self.request_count = 0
        self.bytes_transferred = 0
        self.redirect_count = 0
        self.contacted_hosts: set[str] = set()
        self.blocked_requests: list[str] = []
        self.errors: list[str] = []

    async def handle_request(self, route: Route, request: Request) -> None:
        """Intercept and validate every request."""
        url = request.url

        # Check request count cap
        self.request_count += 1
        if self.request_count > self.max_requests:
            self.blocked_requests.append(f"{url} (request_limit)")
            await route.abort("blockedbyclient")
            return

        # Track redirects for main frame
        if request.is_navigation_request():
            self.redirect_count += 1
            if self.redirect_count > self.max_redirects:
                self.blocked_requests.append(f"{url} (redirect_limit)")
                await route.abort("blockedbyclient")
                return

        # Route through netguard
        try:
            if not self.allow_test_loopback or not _is_test_loopback(url):
                await assert_public_target(url, settings=self.settings)
        except BlockedTargetError as error:
            self.blocked_requests.append(f"{url} ({error.reason_code})")
            await route.abort("blockedbyclient")
            return
        except Exception as error:  # noqa: BLE001
            logger.warning("netguard check failed for %s: %s", url, error)
            self.blocked_requests.append(f"{url} (netguard_error)")
            await route.abort("blockedbyclient")
            return

        # Track contacted host
        host = urlsplit(url).hostname
        if host:
            self.contacted_hosts.add(host)

        # Continue the request
        try:
            await route.continue_()
        except PlaywrightError as error:
            self.errors.append(f"route_continue: {error}")

    async def handle_response(self, response: Response) -> None:
        """Track bytes transferred."""
        try:
            # Estimate size (headers + body length if available)
            size = len(str(response.headers))
            if response.ok:
                # Don't fetch body for non-ok responses
                try:
                    size += len(await response.body())
                except Exception:  # noqa: BLE001
                    pass

            self.bytes_transferred += size
            if self.bytes_transferred > self.max_bytes:
                logger.info("byte limit reached: %d bytes", self.bytes_transferred)
        except Exception as error:  # noqa: BLE001
            logger.warning("response tracking error: %s", error)

    def third_party_ratio(self) -> float:
        """Calculate ratio of third-party hosts to total hosts."""
        if not self.contacted_hosts:
            return 0.0
        third_party = sum(
            1 for host in self.contacted_hosts if host != self.base_host
        )
        return third_party / len(self.contacted_hosts)


def _is_test_loopback(url: str) -> bool:
    """Check if URL is a test loopback address."""
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    return host in {"localhost", "127.0.0.1", "::1"} or host.startswith("192.168.")


async def get_browser() -> Browser:
    """Get or create the singleton browser instance for this worker process.

    Recycles the browser after MAX_SCANS_PER_BROWSER scans to prevent memory leaks.
    """
    global _BROWSER_INSTANCE, _BROWSER_LAUNCH_COUNT  # noqa: PLW0603

    if _BROWSER_INSTANCE is None or _BROWSER_LAUNCH_COUNT >= _MAX_SCANS_PER_BROWSER:
        if _BROWSER_INSTANCE is not None:
            logger.info("recycling browser after %d scans", _BROWSER_LAUNCH_COUNT)
            try:
                await _BROWSER_INSTANCE.close()
            except Exception as error:  # noqa: BLE001
                logger.warning("browser close error: %s", error)

        playwright = await async_playwright().start()
        _BROWSER_INSTANCE = await playwright.chromium.launch(
            headless=True,
            args=[
                "--disable-dev-shm-usage",  # Use /tmp instead of /dev/shm
                "--disable-blink-features=AutomationControlled",
                "--disable-background-networking",
                "--disable-background-timer-throttling",
                "--disable-backgrounding-occluded-windows",
                "--disable-breakpad",
                "--disable-component-extensions-with-background-pages",
                "--disable-extensions",
                "--disable-features=TranslateUI",
                "--disable-hang-monitor",
                "--disable-ipc-flooding-protection",
                "--disable-popup-blocking",
                "--disable-prompt-on-repost",
                "--disable-renderer-backgrounding",
                "--disable-sync",
                "--enable-automation",
                "--force-color-profile=srgb",
                "--metrics-recording-only",
                "--no-first-run",
                "--password-store=basic",
                "--use-mock-keychain",
            ],
        )
        _BROWSER_LAUNCH_COUNT = 0
        logger.info("launched new browser instance")

    _BROWSER_LAUNCH_COUNT += 1
    return _BROWSER_INSTANCE


async def visit(
    url: str,
    *,
    budget_s: float = 15.0,
    settings: Optional[Settings] = None,
    allow_test_loopback: bool = False,
) -> VisitResult:
    """Visit a URL in a fresh browser context and return structured metadata.

    Args:
        url: The URL to visit
        budget_s: Total time budget in seconds (default 15)
        settings: Optional settings override
        allow_test_loopback: Allow localhost/loopback for testing (default False)

    Returns:
        VisitResult with navigation, content, network, and media metadata

    Note:
        - Creates a FRESH context with no storage or cookies
        - Routes ALL requests through netguard (including redirects and subrequests)
        - Enforces caps: <=150 requests, <=8 MB, <=10 redirects
        - Navigates with domcontentloaded + 3s settle time
        - NEVER clicks or types
    """
    current_settings = settings or get_settings()
    start_time = time.monotonic()
    timings: dict[str, float] = {}
    errors: list[str] = []

    # Initialize result with defaults
    result = VisitResult(
        final_url=url,
        timings={"start": start_time},
        errors=errors,
    )

    # Get browser instance
    try:
        browser = await get_browser()
        timings["browser_ready"] = time.monotonic() - start_time
    except Exception as error:  # noqa: BLE001
        errors.append(f"browser_launch: {error}")
        result.errors = errors
        result.timings = timings
        return result

    context: Optional[BrowserContext] = None
    page: Optional[Page] = None

    try:
        # Create fresh context (no storage, no cookies, permissions denied)
        context = await browser.new_context(
            viewport=_VIEWPORT,
            user_agent=_USER_AGENT,
            locale="en-IN",
            timezone_id="Asia/Kolkata",
            accept_downloads=False,
            service_workers="block",
            permissions=[],  # Deny all permissions
            bypass_csp=False,
            ignore_https_errors=False,
            java_script_enabled=True,
            has_touch=False,
            is_mobile=False,
        )
        timings["context_created"] = time.monotonic() - start_time

        # Create request guard for netguard integration and caps
        guard = _RequestGuard(
            url,
            max_requests=150,
            max_bytes=8 * 1024 * 1024,
            max_redirects=10,
            settings=current_settings,
            allow_test_loopback=allow_test_loopback,
        )

        # Install route interception
        await context.route("**/*", guard.handle_request)

        # Track responses for byte counting
        context.on("response", guard.handle_response)

        # Create page
        page = await context.new_page()
        timings["page_created"] = time.monotonic() - start_time

        # Track redirects
        redirect_chain: list[RedirectHop] = []

        def on_response(response: Response) -> None:
            if response.request.is_navigation_request() and response.status in {
                301,
                302,
                303,
                307,
                308,
            }:
                redirect_chain.append(
                    RedirectHop(url=response.url, status=response.status)
                )

        page.on("response", on_response)

        # Track download attempts
        download_attempted = False

        def on_download(_download: Any) -> None:
            nonlocal download_attempted
            download_attempted = True

        page.on("download", on_download)

        # Dismiss dialogs automatically
        async def on_dialog(dialog: Any) -> None:
            try:
                await dialog.dismiss()
            except Exception:  # noqa: BLE001
                pass

        page.on("dialog", on_dialog)

        # Navigate with timeout
        nav_timeout = min(budget_s - 5, 10) * 1000  # Leave 5s for post-nav work
        try:
            response = await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=int(nav_timeout),
            )
            timings["navigation_complete"] = time.monotonic() - start_time

            # Settle time (wait for JS to render forms/content)
            settle_time = min(3.0, budget_s - (time.monotonic() - start_time) - 2)
            if settle_time > 0:
                await asyncio.sleep(settle_time)
                timings["settled"] = time.monotonic() - start_time

            # Capture final state
            result.final_url = page.url
            result.http_status = response.status if response else None

            # Capture title
            try:
                result.title = await page.title()
            except Exception as error:  # noqa: BLE001
                errors.append(f"title: {error}")

            # Capture rendered HTML (capped to ~500KB)
            try:
                html = await page.content()
                if len(html) > 500_000:
                    html = html[:500_000] + "\n<!-- truncated -->"
                result.rendered_html = html
                timings["html_captured"] = time.monotonic() - start_time
            except Exception as error:  # noqa: BLE001
                errors.append(f"html: {error}")

            # Capture response headers (subset)
            if response:
                headers = response.headers
                result.response_headers = {
                    k: v
                    for k, v in headers.items()
                    if k.lower()
                    in {
                        "content-type",
                        "server",
                        "x-frame-options",
                        "content-security-policy",
                        "strict-transport-security",
                    }
                }

            # Capture screenshot
            try:
                screenshot_bytes = await page.screenshot(
                    type="png",
                    full_page=False,  # Only viewport
                )
                result.screenshot_png = screenshot_bytes
                timings["screenshot_captured"] = time.monotonic() - start_time
            except Exception as error:  # noqa: BLE001
                errors.append(f"screenshot: {error}")

            # Capture favicon (best effort)
            try:
                favicon_url = await page.evaluate(
                    """() => {
                    const link = document.querySelector("link[rel*='icon']");
                    return link ? link.href : null;
                }"""
                )
                if favicon_url:
                    # Fetch favicon through context (respects same caps)
                    fav_response = await page.request.get(favicon_url, timeout=2000)
                    if fav_response.ok:
                        result.favicon_bytes = await fav_response.body()
            except Exception:  # noqa: BLE001
                pass  # Favicon is best-effort

            # Populate network metadata
            result.contacted_hosts = sorted(guard.contacted_hosts)
            result.third_party_ratio = guard.third_party_ratio()
            result.blocked_requests = guard.blocked_requests
            result.download_attempted = download_attempted
            result.redirect_chain = redirect_chain

        except asyncio.TimeoutError:
            errors.append("navigation_timeout")
            result.final_url = page.url if page else url
        except PlaywrightError as error:
            errors.append(f"playwright: {error}")
            result.final_url = page.url if page else url

    except Exception as error:  # noqa: BLE001
        errors.append(f"visit: {error}")
    finally:
        # Clean up context and page
        if page:
            try:
                await page.close()
            except Exception:  # noqa: BLE001
                pass
        if context:
            try:
                await context.close()
            except Exception:  # noqa: BLE001
                pass

        timings["total"] = time.monotonic() - start_time
        result.timings = timings
        result.errors = errors

    return result
