"""TLS certificate checks with structured timeout handling.

Checks TLS certificate validity, hostname match, and age (for detecting fresh certs).
All external calls bounded by timeout; never raises into the scan.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from app.core.runner import CheckResult, Signal, check


@dataclass
class TlsInfo:
    """TLS certificate information extracted from a host."""

    available: bool
    subject_cn: Optional[str] = None
    issuer_cn: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    san_hosts: Optional[list[str]] = None
    error: Optional[str] = None


async def get_tls_info(hostname: str, port: int = 443, timeout_s: float = 3.0) -> TlsInfo:
    """Retrieve TLS certificate info from a host within a timeout.

    Args:
        hostname: The hostname to connect to (e.g., "example.com")
        port: TCP port (default 443)
        timeout_s: Connection + handshake timeout in seconds

    Returns:
        TlsInfo with certificate details or error information
    """
    try:
        # Run blocking SSL operations in thread pool with timeout
        loop = asyncio.get_event_loop()
        cert_dict = await asyncio.wait_for(
            loop.run_in_executor(None, _get_server_certificate, hostname, port),
            timeout=timeout_s,
        )

        if cert_dict is None:
            return TlsInfo(available=False, error="no_certificate")

        # Parse certificate fields
        subject = dict(x[0] for x in cert_dict.get("subject", ()))  # type: ignore[arg-type]
        issuer = dict(x[0] for x in cert_dict.get("issuer", ()))  # type: ignore[arg-type]

        subject_cn = subject.get("commonName")
        issuer_cn = issuer.get("commonName")

        not_before = _parse_cert_time(cert_dict.get("notBefore"))
        not_after = _parse_cert_time(cert_dict.get("notAfter"))

        # Parse Subject Alternative Names
        san_hosts: list[str] = []
        for key, value in cert_dict.get("subjectAltName", []):  # type: ignore[arg-type]
            if key == "DNS":
                san_hosts.append(value)

        return TlsInfo(
            available=True,
            subject_cn=subject_cn,
            issuer_cn=issuer_cn,
            not_before=not_before,
            not_after=not_after,
            san_hosts=san_hosts if san_hosts else None,
        )

    except asyncio.TimeoutError:
        return TlsInfo(available=False, error="timeout")
    except socket.gaierror:
        return TlsInfo(available=False, error="dns_failure")
    except ssl.SSLError as err:
        return TlsInfo(available=False, error=f"ssl_error:{err}")
    except (OSError, ConnectionError) as err:
        return TlsInfo(available=False, error=f"connection_error:{type(err).__name__}")
    except Exception as err:  # noqa: BLE001 - must not raise into scan
        return TlsInfo(available=False, error=f"unknown:{type(err).__name__}")


def _get_server_certificate(hostname: str, port: int) -> Optional[dict[str, Any]]:
    """Blocking helper to retrieve server certificate (runs in thread pool).

    Returns:
        Certificate dict or None if connection fails
    """
    context = ssl.create_default_context()
    context.check_hostname = False  # We check hostname manually
    context.verify_mode = ssl.CERT_NONE  # We just want the cert, not full validation

    try:
        with socket.create_connection((hostname, port), timeout=2.0) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(binary_form=False)
                return cert_bin  # type: ignore[return-value]
    except Exception:  # noqa: BLE001 - return None on any failure
        return None


def _parse_cert_time(time_str: Optional[str]) -> Optional[datetime]:
    """Parse certificate notBefore/notAfter time string.

    Args:
        time_str: Time string from certificate (e.g., "Jan 1 00:00:00 2024 GMT")

    Returns:
        datetime in UTC or None if parsing fails
    """
    if not time_str:
        return None
    try:
        # Certificate times are in format: "Jan  1 00:00:00 2024 GMT"
        from datetime import datetime as dt

        dt_obj = dt.strptime(time_str, "%b %d %H:%M:%S %Y %Z")
        return dt_obj.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


def _hostname_matches_cert(hostname: str, tls: TlsInfo) -> bool:
    """Check if hostname matches certificate subject CN or SAN.

    Args:
        hostname: The hostname we connected to
        tls: TLS info containing subject_cn and san_hosts

    Returns:
        True if hostname matches certificate, False otherwise
    """
    if not tls.available:
        return False

    hostname_lower = hostname.lower()

    # Check subject CN
    if tls.subject_cn and _match_hostname_pattern(hostname_lower, tls.subject_cn.lower()):
        return True

    # Check SAN hosts
    if tls.san_hosts:
        for san_host in tls.san_hosts:
            if _match_hostname_pattern(hostname_lower, san_host.lower()):
                return True

    return False


def _match_hostname_pattern(hostname: str, pattern: str) -> bool:
    """Match hostname against certificate pattern (supports wildcards).

    Args:
        hostname: Hostname to check (e.g., "www.example.com")
        pattern: Certificate pattern (e.g., "*.example.com" or "www.example.com")

    Returns:
        True if hostname matches pattern
    """
    if pattern == hostname:
        return True

    # Wildcard pattern (e.g., "*.example.com")
    if pattern.startswith("*."):
        suffix = pattern[2:]
        # Match if hostname ends with suffix and has exactly one more label
        if hostname.endswith("." + suffix):
            # Ensure no additional dots before the suffix
            prefix = hostname[: -(len(suffix) + 1)]
            return "." not in prefix
        # Also match if hostname exactly equals suffix (some certs do this)
        return hostname == suffix

    return False


@check(name="tls_certificate", timeout_s=3.0, group="infrastructure")
async def check_tls_certificate(ctx: Any) -> CheckResult:
    """Check TLS certificate validity, hostname match, and age.

    Signals:
        TLS_CERT_NEW_LT_7D: Certificate issued less than 7 days ago (10 points, medium)
        TLS_HOST_MISMATCH: Hostname does not match certificate (30 points, high)
        TLS_EXPIRED: Certificate has expired (40 points, critical)
        NO_TLS: No TLS certificate available (5 points, low)

    Returns:
        CheckResult with status "ok" (always; unavailable handled by runner timeout)
    """
    url_obj = getattr(ctx, "url", None)
    if not url_obj or not hasattr(url_obj, "host"):
        return CheckResult(
            name="tls_certificate",
            status="skipped",
            group="infrastructure",
            reason="no_host",
        )

    hostname = url_obj.host
    scheme = getattr(url_obj, "scheme", "http")

    # Skip non-HTTPS URLs
    if scheme != "https":
        return CheckResult(
            name="tls_certificate",
            status="ok",
            group="infrastructure",
            detail={"skipped_reason": "non_https"},
        )

    # Get TLS info (bounded by runner's check timeout)
    tls_info = await get_tls_info(hostname, port=443, timeout_s=2.5)

    signals: list[Signal] = []
    detail: dict[str, Any] = {
        "hostname": hostname,
        "available": tls_info.available,
    }

    if not tls_info.available:
        signals.append(
            Signal(
                id="NO_TLS",
                points=5,
                severity="low",
                explain=f"No TLS certificate available: {tls_info.error or 'unknown'}",
                evidence={"error": tls_info.error},
            )
        )
        detail["error"] = tls_info.error
        return CheckResult(
            name="tls_certificate",
            status="ok",
            group="infrastructure",
            signals=signals,
            detail=detail,
        )

    # TLS available - add certificate details
    detail.update(
        {
            "subject_cn": tls_info.subject_cn,
            "issuer_cn": tls_info.issuer_cn,
            "not_before": tls_info.not_before.isoformat() if tls_info.not_before else None,
            "not_after": tls_info.not_after.isoformat() if tls_info.not_after else None,
            "san_hosts": tls_info.san_hosts,
        }
    )

    now = datetime.now(timezone.utc)

    # Check 1: Certificate expired
    if tls_info.not_after and tls_info.not_after < now:
        signals.append(
            Signal(
                id="TLS_EXPIRED",
                points=40,
                severity="critical",
                explain="TLS certificate has expired",
                evidence={
                    "expired_at": tls_info.not_after.isoformat(),
                },
            )
        )

    # Check 2: Hostname mismatch
    if not _hostname_matches_cert(hostname, tls_info):
        signals.append(
            Signal(
                id="TLS_HOST_MISMATCH",
                points=30,
                severity="high",
                explain=f"Hostname '{hostname}' does not match certificate",
                evidence={
                    "subject_cn": tls_info.subject_cn,
                    "san_hosts": tls_info.san_hosts,
                },
            )
        )

    # Check 3: Certificate issued less than 7 days ago (fresh cert, suspicious for phishing)
    if tls_info.not_before:
        age_days = (now - tls_info.not_before).total_seconds() / 86400
        detail["cert_age_days"] = round(age_days, 2)

        if age_days < 7:
            signals.append(
                Signal(
                    id="TLS_CERT_NEW_LT_7D",
                    points=10,
                    severity="medium",
                    explain=f"Certificate issued {round(age_days, 1)} days ago (fresh certificates are sometimes used for phishing)",
                    evidence={
                        "issued_at": tls_info.not_before.isoformat(),
                        "age_days": round(age_days, 2),
                    },
                )
            )

    return CheckResult(
        name="tls_certificate",
        status="ok",
        group="infrastructure",
        signals=signals,
        detail=detail,
    )
