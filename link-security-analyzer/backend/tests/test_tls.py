"""Tests for TLS certificate checking."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.runner import CheckResult
from app.core.tls import (
    _hostname_matches_cert,
    _match_hostname_pattern,
    _parse_cert_time,
    check_tls_certificate,
    get_tls_info,
    TlsInfo,
)


class TestTlsInfo:
    """Test TLS info retrieval with various scenarios."""

    @pytest.mark.asyncio
    async def test_get_tls_info_timeout(self):
        """Timeout returns unavailable TlsInfo."""
        with patch("app.core.tls.asyncio.wait_for", side_effect=TimeoutError):
            result = await get_tls_info("example.com", timeout_s=1.0)
            assert result.available is False
            assert result.error == "timeout"

    @pytest.mark.asyncio
    async def test_get_tls_info_dns_failure(self):
        """DNS resolution failure returns unavailable TlsInfo."""
        import socket

        with patch(
            "app.core.tls._get_server_certificate", side_effect=socket.gaierror
        ):
            with patch("app.core.tls.asyncio.wait_for", side_effect=socket.gaierror):
                result = await get_tls_info("nonexistent.invalid", timeout_s=1.0)
                assert result.available is False
                assert result.error == "dns_failure"

    @pytest.mark.asyncio
    async def test_get_tls_info_success(self):
        """Valid certificate returns TlsInfo with parsed fields."""
        mock_cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Example CA"),),),
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": "Dec 31 23:59:59 2024 GMT",
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        }

        with patch("app.core.tls._get_server_certificate", return_value=mock_cert):
            with patch(
                "app.core.tls.asyncio.wait_for",
                side_effect=lambda coro, timeout: coro,
            ):
                result = await get_tls_info("example.com", timeout_s=1.0)

        assert result.available is True
        assert result.subject_cn == "example.com"
        assert result.issuer_cn == "Example CA"
        assert result.not_before is not None
        assert result.not_after is not None
        assert result.san_hosts == ["example.com", "www.example.com"]
        assert result.error is None


class TestParseCertTime:
    """Test certificate time parsing."""

    def test_parse_valid_cert_time(self):
        """Valid cert time string parses to UTC datetime."""
        result = _parse_cert_time("Jan  1 00:00:00 2024 GMT")
        assert result is not None
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 1
        assert result.tzinfo == timezone.utc

    def test_parse_invalid_cert_time(self):
        """Invalid time string returns None."""
        assert _parse_cert_time("invalid") is None
        assert _parse_cert_time(None) is None
        assert _parse_cert_time("") is None


class TestMatchHostnamePattern:
    """Test hostname pattern matching for certificates."""

    def test_exact_match(self):
        """Exact hostname matches."""
        assert _match_hostname_pattern("example.com", "example.com") is True
        assert _match_hostname_pattern("www.example.com", "www.example.com") is True

    def test_wildcard_match(self):
        """Wildcard pattern matches correctly."""
        assert _match_hostname_pattern("www.example.com", "*.example.com") is True
        assert _match_hostname_pattern("api.example.com", "*.example.com") is True

    def test_wildcard_no_match_extra_subdomain(self):
        """Wildcard does not match nested subdomains."""
        assert _match_hostname_pattern("a.b.example.com", "*.example.com") is False

    def test_wildcard_matches_base(self):
        """Wildcard may match base domain (some certs do this)."""
        assert _match_hostname_pattern("example.com", "*.example.com") is True

    def test_no_match(self):
        """Unrelated hostnames do not match."""
        assert _match_hostname_pattern("example.com", "other.com") is False
        assert _match_hostname_pattern("example.com", "*.other.com") is False


class TestHostnameMatchesCert:
    """Test hostname verification against certificate."""

    def test_matches_subject_cn(self):
        """Hostname matches certificate subject CN."""
        tls_info = TlsInfo(
            available=True,
            subject_cn="example.com",
            san_hosts=None,
        )
        assert _hostname_matches_cert("example.com", tls_info) is True

    def test_matches_san(self):
        """Hostname matches certificate SAN."""
        tls_info = TlsInfo(
            available=True,
            subject_cn="example.com",
            san_hosts=["www.example.com", "api.example.com"],
        )
        assert _hostname_matches_cert("www.example.com", tls_info) is True

    def test_matches_wildcard_san(self):
        """Hostname matches wildcard SAN."""
        tls_info = TlsInfo(
            available=True,
            subject_cn="example.com",
            san_hosts=["*.example.com"],
        )
        assert _hostname_matches_cert("www.example.com", tls_info) is True

    def test_no_match(self):
        """Hostname does not match certificate."""
        tls_info = TlsInfo(
            available=True,
            subject_cn="example.com",
            san_hosts=["www.example.com"],
        )
        assert _hostname_matches_cert("other.com", tls_info) is False

    def test_unavailable_cert_no_match(self):
        """Unavailable certificate never matches."""
        tls_info = TlsInfo(available=False, error="timeout")
        assert _hostname_matches_cert("example.com", tls_info) is False


class TestCheckTlsCertificate:
    """Test TLS certificate runner check."""

    @pytest.mark.asyncio
    async def test_skipped_no_host(self):
        """Check skipped when no host in context."""
        ctx = MagicMock()
        ctx.url = None

        result = await check_tls_certificate(ctx)
        assert result.status == "skipped"
        assert result.reason == "no_host"

    @pytest.mark.asyncio
    async def test_skipped_non_https(self):
        """Check skipped for non-HTTPS URLs."""
        ctx = MagicMock()
        ctx.url = MagicMock(host="example.com", scheme="http")

        result = await check_tls_certificate(ctx)
        assert result.status == "ok"
        assert result.detail.get("skipped_reason") == "non_https"
        assert len(result.signals) == 0

    @pytest.mark.asyncio
    async def test_no_tls_signal(self):
        """NO_TLS signal when certificate unavailable."""
        ctx = MagicMock()
        ctx.url = MagicMock(host="example.com", scheme="https")

        with patch(
            "app.core.tls.get_tls_info",
            return_value=TlsInfo(available=False, error="timeout"),
        ):
            result = await check_tls_certificate(ctx)

        assert result.status == "ok"
        assert len(result.signals) == 1
        assert result.signals[0].id == "NO_TLS"
        assert result.signals[0].severity == "low"
        assert result.signals[0].points == 5

    @pytest.mark.asyncio
    async def test_expired_certificate_signal(self):
        """TLS_EXPIRED signal when certificate has expired."""
        ctx = MagicMock()
        ctx.url = MagicMock(host="example.com", scheme="https")

        expired_time = datetime.now(timezone.utc) - timedelta(days=10)
        tls_info = TlsInfo(
            available=True,
            subject_cn="example.com",
            not_before=datetime.now(timezone.utc) - timedelta(days=400),
            not_after=expired_time,
            san_hosts=["example.com"],
        )

        with patch("app.core.tls.get_tls_info", return_value=tls_info):
            result = await check_tls_certificate(ctx)

        assert result.status == "ok"
        expired_signal = next((s for s in result.signals if s.id == "TLS_EXPIRED"), None)
        assert expired_signal is not None
        assert expired_signal.severity == "critical"
        assert expired_signal.points == 40

    @pytest.mark.asyncio
    async def test_hostname_mismatch_signal(self):
        """TLS_HOST_MISMATCH signal when hostname doesn't match certificate."""
        ctx = MagicMock()
        ctx.url = MagicMock(host="other.com", scheme="https")

        tls_info = TlsInfo(
            available=True,
            subject_cn="example.com",
            not_before=datetime.now(timezone.utc) - timedelta(days=100),
            not_after=datetime.now(timezone.utc) + timedelta(days=200),
            san_hosts=["example.com", "www.example.com"],
        )

        with patch("app.core.tls.get_tls_info", return_value=tls_info):
            result = await check_tls_certificate(ctx)

        assert result.status == "ok"
        mismatch_signal = next(
            (s for s in result.signals if s.id == "TLS_HOST_MISMATCH"), None
        )
        assert mismatch_signal is not None
        assert mismatch_signal.severity == "high"
        assert mismatch_signal.points == 30

    @pytest.mark.asyncio
    async def test_new_certificate_signal(self):
        """TLS_CERT_NEW_LT_7D signal when certificate is less than 7 days old."""
        ctx = MagicMock()
        ctx.url = MagicMock(host="example.com", scheme="https")

        tls_info = TlsInfo(
            available=True,
            subject_cn="example.com",
            not_before=datetime.now(timezone.utc) - timedelta(days=3),
            not_after=datetime.now(timezone.utc) + timedelta(days=87),
            san_hosts=["example.com"],
        )

        with patch("app.core.tls.get_tls_info", return_value=tls_info):
            result = await check_tls_certificate(ctx)

        assert result.status == "ok"
        new_cert_signal = next(
            (s for s in result.signals if s.id == "TLS_CERT_NEW_LT_7D"), None
        )
        assert new_cert_signal is not None
        assert new_cert_signal.severity == "medium"
        assert new_cert_signal.points == 10
        assert "age_days" in new_cert_signal.evidence

    @pytest.mark.asyncio
    async def test_valid_certificate_no_signals(self):
        """Valid certificate matching hostname produces no signals."""
        ctx = MagicMock()
        ctx.url = MagicMock(host="example.com", scheme="https")

        tls_info = TlsInfo(
            available=True,
            subject_cn="example.com",
            not_before=datetime.now(timezone.utc) - timedelta(days=30),
            not_after=datetime.now(timezone.utc) + timedelta(days=60),
            san_hosts=["example.com", "www.example.com"],
        )

        with patch("app.core.tls.get_tls_info", return_value=tls_info):
            result = await check_tls_certificate(ctx)

        assert result.status == "ok"
        assert len(result.signals) == 0
        assert result.detail["available"] is True
        assert "cert_age_days" in result.detail
