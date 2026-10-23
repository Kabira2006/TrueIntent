"""Disposable Chromium analysis of hostile pages with per-request network checks."""

import asyncio
import ipaddress
import logging
import re
from io import BytesIO
from typing import Any, Literal
from urllib.parse import urljoin, urlsplit, urlunsplit

import imagehash
import tldextract
from bs4 import BeautifulSoup
from PIL import Image
from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Request,
    Route,
    WebSocketRoute,
    async_playwright,
)
from playwright.async_api import (
    Error as PlaywrightError,
)
from pydantic import BaseModel, ConfigDict

from app.config import Settings, get_settings
from app.core.models import Indicator
from app.core.netguard import BlockedTargetError, assert_public_target

logger = logging.getLogger(__name__)
_VIEWPORT = {"width": 1280, "height": 720}
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
)
_SHORTENER_HOSTS = {
    "bit.ly",
    "buff.ly",
    "goo.gl",
    "is.gd",
    "t.co",
    "tinyurl.com",
    "ow.ly",
}
_SENSITIVE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "otp",
        re.compile(
            r"\b(?:otp|one.?time.?password|verification.?code)\b", re.IGNORECASE
        ),
    ),
    ("upi_pin", re.compile(r"\bupi[\s_-]*pin\b", re.IGNORECASE)),
    (
        "card_number",
        re.compile(r"\b(?:card.?number|credit.?card|debit.?card)\b", re.IGNORECASE),
    ),
    ("security_code", re.compile(r"\b(?:cvv|cvc|security.?code)\b", re.IGNORECASE)),
    ("aadhaar", re.compile(r"\b(?:aadhaar|aadhar)\b", re.IGNORECASE)),
)
_NAVIGATION_STATUSES = {301, 302, 303, 307, 308}
_SUFFIX_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


class SandboxResult(BaseModel):
    """Pillar data produced by one throwaway browser context."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["NO_INDICATORS", "FLAGGED", "UNAVAILABLE"]
    indicators: list[Indicator]
    features: dict[str, str | int | float | bool]


def hamming_distance(left_hash: str, right_hash: str) -> int:
    """Return the differing-bit count for two hexadecimal 64-bit hashes."""
    if not re.fullmatch(r"[0-9a-fA-F]{1,16}", left_hash) or not re.fullmatch(
        r"[0-9a-fA-F]{1,16}", right_hash
    ):
        raise ValueError("Perceptual hashes must be hexadecimal values up to 64 bits.")
    return (int(left_hash, 16) ^ int(right_hash, 16)).bit_count()


def match_brand_references(
    page_hash: str | None,
    page_host: str | None,
    references: list[Any],
    *,
    threshold: int,
) -> list[Indicator]:
    """Compare a page hash to official references, excluding official domains."""
    if not page_hash or not page_host:
        return []
    if not 0 <= threshold <= 64:
        raise ValueError("The perceptual-hash threshold must be between 0 and 64.")

    page_domain = _registered_domain(page_host)
    if not page_domain:
        return []
    distances: dict[tuple[str, str], int] = {}
    for reference in references:
        brand = str(_reference_value(reference, "brand_name", "")).strip()
        official = str(_reference_value(reference, "official_domain", "")).strip()
        reference_hash = _reference_value(reference, "phash_signature")
        if not brand or not official or not isinstance(reference_hash, str):
            continue
        official_domain = _registered_domain(official)
        if not official_domain or page_domain == official_domain:
            continue
        try:
            distance = hamming_distance(page_hash, reference_hash)
        except ValueError:
            logger.warning("ignored invalid perceptual hash for brand=%s", brand)
            continue
        key = (brand, official_domain)
        distances[key] = min(distance, distances.get(key, 65))

    indicators: list[Indicator] = []
    for (brand, _official_domain), distance in sorted(distances.items()):
        if distance <= threshold:
            indicators.append(
                _indicator(
                    "VISUAL_BRAND_IMPERSONATION",
                    "high",
                    f"The page layout resembles the {brand} reference, but the domain is not the brand's official domain.",
                    {"brand": brand, "distance": distance, "threshold": threshold},
                )
            )
        elif distance <= threshold + 4:
            indicators.append(
                _indicator(
                    "VISUAL_SIMILARITY_WEAK",
                    "low",
                    f"The page layout resembles the {brand} reference, but the domain is not the brand's official domain.",
                    {"brand": brand, "distance": distance, "threshold": threshold},
                )
            )
    return indicators


def _reference_value(reference: Any, key: str, default: Any = None) -> Any:
    if isinstance(reference, dict):
        return reference.get(key, default)
    return getattr(reference, key, default)


def _registered_domain(value: str) -> str | None:
    host = _hostname(value if "://" in value else f"https://{value}")
    if not host:
        return None
    extracted = _SUFFIX_EXTRACTOR(host)
    return extracted.top_domain_under_public_suffix or host


class RequestGuard:
    """Route browser requests only after validating their destination."""

    def __init__(
        self,
        indicators: list[Indicator],
        *,
        max_navigations: int,
        test_origin: tuple[str, int] | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.indicators = indicators
        self.max_navigations = max_navigations
        self.test_origin = test_origin
        self.settings = settings or get_settings()
        self.navigation_count = 0

    async def handle(self, route: Route, request: Request) -> None:
        url = request.url
        parsed = urlsplit(url)
        try:
            if not self._is_explicit_test_target(parsed):
                await assert_public_target(url, settings=self.settings)
        except BlockedTargetError as error:
            self._blocked(url, error.reason_code)
            await _abort_route(route)
            return

        if parsed.scheme.lower() not in {"http", "https"}:
            self._blocked(url, "UNSUPPORTED_SCHEME")
            await _abort_route(route)
            return
        if request.is_navigation_request():
            self.navigation_count += 1
            if self.navigation_count > self.max_navigations:
                self._blocked(url, "NAVIGATION_LIMIT")
                await _abort_route(route)
                return
        if request.resource_type == "media":
            self._blocked(url, "DISALLOWED_RESOURCE_TYPE")
            await _abort_route(route)
            return
        try:
            await route.continue_()
        except PlaywrightError as error:
            if "closed" not in str(error).lower():
                raise

    async def handle_websocket(self, route: WebSocketRoute) -> None:
        url = route.url
        parsed = urlsplit(url)
        reason = "WEBSOCKET"
        if parsed.scheme in {"ws", "wss"}:
            target = parsed._replace(
                scheme="https" if parsed.scheme == "wss" else "http"
            ).geturl()
            try:
                await assert_public_target(target, settings=self.settings)
            except BlockedTargetError as error:
                reason = error.reason_code
        else:
            reason = "UNSUPPORTED_SCHEME"
        self._blocked(url, reason)
        try:
            await route.close(code=1008, reason="WebSocket connections are disabled.")
        except PlaywrightError as error:
            if "closed" not in str(error).lower():
                raise

    def _is_explicit_test_target(self, parsed: Any) -> bool:
        if self.test_origin is None:
            return False
        try:
            address = ipaddress.ip_address(parsed.hostname or "")
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            return False
        return (
            parsed.scheme == "http"
            and address.is_loopback
            and (str(address), port) == self.test_origin
        )

    def _blocked(self, url: str, reason: str) -> None:
        host = _hostname(url)
        self.indicators.append(
            _indicator(
                "SANDBOX_BLOCKED_REQUEST",
                "medium",
                "The page attempted a request that the browser sandbox blocked.",
                {"host": host or "unknown", "reason": reason},
            )
        )


async def scan_page(
    url: str,
    *,
    domain_age_days: int | None = None,
    settings: Settings | None = None,
    _allow_local_test_targets: bool = False,
) -> SandboxResult:
    """Inspect one URL in a new browser and context, then close both."""
    current_settings = settings or get_settings()
    indicators: list[Indicator] = []
    test_origin = _test_loopback_origin(url) if _allow_local_test_targets else None
    try:
        if test_origin is None:
            await assert_public_target(url, settings=current_settings)
    except BlockedTargetError as error:
        guard = RequestGuard(
            indicators, max_navigations=current_settings.sandbox_max_navigations
        )
        guard._blocked(url, error.reason_code)
        return _result(indicators, {})

    return await asyncio.wait_for(
        _scan_page_in_browser(
            url,
            current_settings,
            domain_age_days=domain_age_days,
            test_origin=test_origin,
            indicators=indicators,
        ),
        timeout=current_settings.sandbox_page_timeout_seconds + 10,
    )


async def _scan_page_in_browser(
    url: str,
    settings: Settings,
    *,
    domain_age_days: int | None,
    test_origin: tuple[str, int] | None,
    indicators: list[Indicator],
) -> SandboxResult:
    browser: Browser | None = None
    context: BrowserContext | None = None
    features: dict[str, str | int | float | bool] = {}
    chain_hosts: list[str] = []
    redirect_state = {"http_redirects": 0, "last_navigation_url": ""}
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=True, chromium_sandbox=True
            )
            context = await browser.new_context(
                viewport=_VIEWPORT,
                user_agent=_USER_AGENT,
                service_workers="block",
                permissions=[],
                accept_downloads=False,
            )
            guard = RequestGuard(
                indicators,
                max_navigations=settings.sandbox_max_navigations,
                test_origin=test_origin,
                settings=settings,
            )
            await context.route("**/*", guard.handle)
            await context.route_web_socket("**/*", guard.handle_websocket)
            page = await context.new_page()
            _track_redirects(page, chain_hosts, redirect_state)
            page.on("dialog", _dismiss_dialog)
            page.on(
                "download",
                lambda download: asyncio.create_task(_cancel_download(download)),
            )
            await _track_network_bytes(
                page, context, settings.sandbox_max_bytes, indicators
            )
            await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=settings.sandbox_page_timeout_seconds * 1000,
            )
            if page.is_closed():
                return SandboxResult(
                    status="UNAVAILABLE",
                    indicators=indicators,
                    features=features,
                )

            final_host = _hostname(page.url)
            if final_host:
                _append_host(chain_hosts, final_host)
            _redirect_indicators(
                chain_hosts, indicators, redirect_state["http_redirects"]
            )

            html = await page.content()
            if len(html.encode("utf-8")) > settings.sandbox_max_bytes:
                indicators.append(
                    _indicator(
                        "SANDBOX_BYTE_LIMIT_REACHED",
                        "info",
                        "Page content exceeded the configured analysis size limit.",
                        {"maximum_bytes": settings.sandbox_max_bytes},
                    )
                )
                return SandboxResult(
                    status="UNAVAILABLE",
                    indicators=indicators,
                    features=features,
                )

            indicators.extend(
                audit_dom(
                    html,
                    page.url,
                    domain_age_days=domain_age_days,
                )
            )
            screenshot = await page.screenshot(
                type="png",
                full_page=False,
                animations="disabled",
                timeout=settings.sandbox_page_timeout_seconds * 1000,
            )
            with Image.open(BytesIO(screenshot)) as image:
                phash = str(imagehash.phash(image))
            features["phash"] = phash
            del screenshot
            features["redirect_chain_hosts"] = " -> ".join(chain_hosts)
            features["final_host"] = final_host or ""
            features["final_url"] = _without_query(page.url)
            return _result(indicators, features)
    except (TimeoutError, PlaywrightError) as error:
        logger.info("sandbox browser unavailable (%s)", type(error).__name__)
        indicators.append(
            _indicator(
                "SANDBOX_UNAVAILABLE",
                "info",
                "The browser check could not be completed within its limits.",
                {"reason": type(error).__name__},
            )
        )
        return SandboxResult(
            status="UNAVAILABLE",
            indicators=indicators,
            features=features,
        )
    finally:
        if context is not None:
            try:
                await context.unroute_all(behavior="wait")
                await context.close()
            except PlaywrightError as error:
                logger.info("sandbox context close failed (%s)", type(error).__name__)
        if browser is not None:
            try:
                await browser.close()
            except PlaywrightError as error:
                logger.info("sandbox browser close failed (%s)", type(error).__name__)


def audit_dom(
    html: str,
    page_url: str,
    *,
    domain_age_days: int | None = None,
) -> list[Indicator]:
    """Report forms and hidden page elements without retaining entered values."""
    soup = BeautifulSoup(html, "html.parser")
    indicators: list[Indicator] = []
    page_host = _hostname(page_url)
    sensitive_kinds: set[str] = set()
    has_password = False
    has_login_form = False

    for form in soup.find_all("form"):
        action = urljoin(page_url, str(form.get("action") or page_url))
        action_host = _hostname(action)
        method = str(form.get("method") or "get").lower()
        if action_host and page_host and action_host != page_host:
            indicators.append(
                _indicator(
                    "FORM_POSTS_TO_DIFFERENT_DOMAIN",
                    "medium",
                    "A form sends its data to a different host than the page.",
                    {"page_host": page_host, "action_host": action_host},
                )
            )
        if method == "post" and urlsplit(action).scheme.lower() == "http":
            indicators.append(
                _indicator(
                    "FORM_POSTS_OVER_HTTP",
                    "medium",
                    "A form sends submitted data without HTTPS transport.",
                    {"action_host": action_host or "unknown"},
                )
            )

        form_text = " ".join(form.stripped_strings).lower()
        has_password |= bool(form.select('input[type="password"]'))
        has_login_form |= bool(form.select('input[type="password"]')) or (
            "login" in form_text or "sign in" in form_text
        )
        for field in form.find_all(["input", "textarea"]):
            field_text = _field_description(field)
            for kind, pattern in _SENSITIVE_PATTERNS:
                if pattern.search(field_text):
                    sensitive_kinds.add(kind)

    if has_password:
        indicators.append(
            _indicator(
                "PASSWORD_FIELD_PRESENT",
                "info",
                "The page contains a password entry field.",
                {"field_type": "password"},
            )
        )
    if sensitive_kinds:
        indicators.append(
            _indicator(
                "SENSITIVE_FIELD_REQUESTED",
                "medium",
                "The page requests one or more sensitive authentication or payment details.",
                {"field_types": ", ".join(sorted(sensitive_kinds))},
            )
        )
    if has_login_form and domain_age_days is not None and domain_age_days < 30:
        indicators.append(
            _indicator(
                "NEW_DOMAIN_LOGIN_FORM",
                "medium",
                "A login-like form appears on a recently registered domain.",
                {"domain_age_days": domain_age_days},
            )
        )

    for iframe in soup.find_all("iframe"):
        style = str(iframe.get("style") or "").lower().replace(" ", "")
        hidden = (
            iframe.has_attr("hidden")
            or str(iframe.get("aria-hidden", "")).lower() == "true"
            or "display:none" in style
            or "visibility:hidden" in style
            or iframe.get("width") == "0"
            or iframe.get("height") == "0"
        )
        if hidden:
            indicators.append(
                _indicator(
                    "HIDDEN_IFRAME",
                    "low",
                    "The page contains an iframe hidden from view.",
                    {"count": 1},
                )
            )
            break

    if soup.find("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.IGNORECASE)}):
        indicators.append(
            _indicator(
                "META_REFRESH_REDIRECT",
                "low",
                "The page contains a browser meta-refresh navigation.",
                {"mechanism": "meta-refresh"},
            )
        )
    return indicators


def _field_description(field: Any) -> str:
    details = [
        str(field.get(key) or "")
        for key in ("name", "id", "placeholder", "aria-label", "autocomplete")
    ]
    field_id = field.get("id")
    if field_id:
        label = field.find_parent("label")
        if label is not None:
            details.append(label.get_text(" ", strip=True))
        for label in field.find_parent().find_all("label", attrs={"for": field_id}):
            details.append(label.get_text(" ", strip=True))
    return " ".join(details)


def _track_redirects(
    page: Page,
    chain_hosts: list[str],
    state: dict[str, str | int],
) -> None:
    def on_request(request: Request) -> None:
        if not request.is_navigation_request():
            return
        last_url = str(state["last_navigation_url"])
        if (
            request.redirected_from is not None
            or not chain_hosts
            or request.url != last_url
        ):
            _record_navigation(chain_hosts, _hostname(request.url))
        state["last_navigation_url"] = request.url

    def on_response(response: Any) -> None:
        if (
            response.request.is_navigation_request()
            and response.status in _NAVIGATION_STATUSES
        ):
            state["http_redirects"] = int(state["http_redirects"]) + 1

    def on_frame_navigated(frame: Any) -> None:
        if frame == page.main_frame and frame.url != state["last_navigation_url"]:
            _record_navigation(chain_hosts, _hostname(frame.url))
            state["last_navigation_url"] = frame.url

    page.on("request", on_request)
    page.on("response", on_response)
    page.on("framenavigated", on_frame_navigated)


async def _track_network_bytes(
    page: Page,
    context: Any,
    maximum: int,
    indicators: list[Indicator],
) -> None:
    session = await context.new_cdp_session(page)
    await session.send("Network.enable")
    total = 0
    limit_reached = False

    def on_data_received(event: dict[str, Any]) -> None:
        nonlocal total, limit_reached
        total += int(event.get("encodedDataLength", 0))
        if total > maximum and not limit_reached:
            limit_reached = True
            indicators.append(
                _indicator(
                    "SANDBOX_BYTE_LIMIT_REACHED",
                    "info",
                    "The browser stopped loading after the response-size limit was reached.",
                    {"maximum_bytes": maximum},
                )
            )
            asyncio.create_task(_close_page(page))

    session.on("Network.dataReceived", on_data_received)


async def _dismiss_dialog(dialog: Any) -> None:
    try:
        await dialog.dismiss()
    except PlaywrightError as error:
        logger.info("sandbox dialog dismissal failed (%s)", type(error).__name__)


async def _abort_route(route: Route) -> None:
    try:
        await route.abort("blockedbyclient")
    except PlaywrightError as error:
        if "closed" not in str(error).lower():
            raise


async def _cancel_download(download: Any) -> None:
    try:
        await download.cancel()
    except PlaywrightError as error:
        if "closed" not in str(error).lower():
            logger.info(
                "sandbox download cancellation failed (%s)", type(error).__name__
            )


async def _close_page(page: Page) -> None:
    try:
        if not page.is_closed():
            await page.close()
    except PlaywrightError as error:
        logger.info("sandbox page close failed (%s)", type(error).__name__)


def _redirect_indicators(
    chain_hosts: list[str],
    indicators: list[Indicator],
    http_redirect_count: int,
) -> None:
    if http_redirect_count > 3:
        indicators.append(
            _indicator(
                "REDIRECT_CHAIN_LONG",
                "low",
                "The page navigated through several hosts before reaching its final page.",
                {"navigation_hosts": " -> ".join(chain_hosts)},
            )
        )
    if len(set(chain_hosts)) > 1:
        indicators.append(
            _indicator(
                "REDIRECT_CROSS_DOMAIN",
                "low",
                "The navigation chain crossed between different hosts.",
                {"navigation_hosts": " -> ".join(chain_hosts)},
            )
        )
    if any(host in _SHORTENER_HOSTS for host in chain_hosts):
        indicators.append(
            _indicator(
                "REDIRECT_TO_SHORTENER",
                "info",
                "The navigation chain included a known link-shortening host.",
                {"navigation_hosts": " -> ".join(chain_hosts)},
            )
        )


def _append_host(chain_hosts: list[str], host: str | None) -> None:
    if host and (not chain_hosts or chain_hosts[-1] != host):
        chain_hosts.append(host)


def _record_navigation(chain_hosts: list[str], host: str | None) -> None:
    if host:
        chain_hosts.append(host)


def _without_query(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _hostname(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def _test_loopback_origin(url: str) -> tuple[str, int] | None:
    """Test-only escape hatch, usable only for an explicit literal loopback URL."""
    try:
        parsed = urlsplit(url)
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None
    if parsed.scheme != "http" or not address.is_loopback:
        return None
    return str(address), port


def _indicator(
    code: str,
    severity: Literal["info", "low", "medium", "high"],
    message: str,
    evidence: dict[str, str | int | float | bool | None],
) -> Indicator:
    return Indicator(
        code=code,
        severity=severity,
        message=message,
        evidence=evidence,
    )


def _result(
    indicators: list[Indicator],
    features: dict[str, str | int | float | bool],
) -> SandboxResult:
    return SandboxResult(
        status="FLAGGED" if indicators else "NO_INDICATORS",
        indicators=indicators,
        features=features,
    )
