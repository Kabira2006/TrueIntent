"""SSRF prevention test suite: comprehensive test coverage for netguard.

Tests at least 50 different bypass attempts:
- Loopback variants (127.0.0.1, 127.1, 0x7f000001, octal, IPv6)
- Private ranges (10/8, 172.16/12, 192.168/16, fc00::/7)
- Link-local and cloud metadata (169.254.169.254, fd00:ec2::254)
- CGNAT (100.64.0.0/10)
- Special addresses (0.0.0.0, IPv6 zone IDs)
- Localhost aliases
- Credentials in URL
- DNS names resolving to private IPs (fake resolver)
- Unusual schemes (file://, ftp://, gopher://, javascript:, data:)
"""

import ipaddress
from unittest.mock import AsyncMock, MagicMock, patch

import dns.asyncresolver
import pytest

from app.core.netguard import BlockedTargetError, assert_public_target


class TestLoopbackVariants:
    """Test various loopback address representations."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "target",
        [
            # Standard dotted decimal
            "http://127.0.0.1",
            "http://127.0.0.1:8080",
            "https://127.0.0.1",
            # Abbreviated forms
            "http://127.1",
            "http://127.0.1",
            # Decimal representation
            "http://2130706433",  # 127.0.0.1 in decimal
            # Hex representation
            "http://0x7f000001",  # 127.0.0.1 in hex
            "http://0x7F000001",  # uppercase
            # Octal representation
            "http://0177.0.0.1",  # 127 in octal
            "http://0177.0.0.01",
            "http://0177.0.01",
            # Mixed formats
            "http://0x7f.0.0.1",
            "http://127.0.0x01",
            # IPv6 loopback
            "http://[::1]",
            "http://[::1]:8080",
            "https://[::1]",
            "http://[0:0:0:0:0:0:0:1]",
            # IPv4-mapped IPv6 loopback
            "http://[::ffff:127.0.0.1]",
            "http://[::ffff:7f00:1]",
            # Other loopback range addresses
            "http://127.255.255.255",
            "http://127.100.50.25",
        ],
    )
    async def test_loopback_blocked(self, target: str) -> None:
        """All loopback representations must be blocked."""
        with pytest.raises(BlockedTargetError) as exc_info:
            await assert_public_target(target)
        assert exc_info.value.reason_code == "NON_PUBLIC_ADDRESS"


class TestPrivateRanges:
    """Test private IP address ranges."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "target",
        [
            # 10.0.0.0/8 (Class A private)
            "http://10.0.0.0",
            "http://10.0.0.1",
            "http://10.255.255.255",
            "http://10.1.2.3:8080",
            # 172.16.0.0/12 (Class B private)
            "http://172.16.0.0",
            "http://172.16.0.1",
            "http://172.31.255.255",
            "http://172.20.50.100",
            # 192.168.0.0/16 (Class C private)
            "http://192.168.0.0",
            "http://192.168.0.1",
            "http://192.168.255.255",
            "http://192.168.1.1:443",
            # IPv6 unique local (fc00::/7)
            "http://[fc00::1]",
            "http://[fd00::1]",
            "http://[fd12:3456:789a:bcde::1]",
            # Private ranges in numeric forms
            "http://167772160",  # 10.0.0.0 in decimal
            "http://0xa000001",  # 10.0.0.1 in hex
            "http://012.0.0.1",  # 10 in octal (012 = 10)
        ],
    )
    async def test_private_ranges_blocked(self, target: str) -> None:
        """Private IP ranges must be blocked."""
        with pytest.raises(BlockedTargetError) as exc_info:
            await assert_public_target(target)
        assert exc_info.value.reason_code == "NON_PUBLIC_ADDRESS"


class TestLinkLocalAndMetadata:
    """Test link-local and cloud metadata endpoints."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "target",
        [
            # AWS/Azure/GCP metadata endpoint
            "http://169.254.169.254",
            "http://169.254.169.254/latest/meta-data/",
            "https://169.254.169.254",
            # Other link-local addresses (169.254.0.0/16)
            "http://169.254.0.1",
            "http://169.254.255.255",
            "http://169.254.1.1:8080",
            # IPv6 link-local (fe80::/10)
            "http://[fe80::1]",
            "http://[fe80::dead:beef]",
            "http://[fe80::1%eth0]",  # with zone ID
            "http://[fe80::1%25eth0]",  # URL-encoded zone ID
            # AWS IPv6 metadata (example)
            "http://[fd00:ec2::254]",
            # Numeric forms of metadata IP
            "http://2852039166",  # 169.254.169.254 in decimal
            "http://0xa9fea9fe",  # 169.254.169.254 in hex
        ],
    )
    async def test_link_local_metadata_blocked(self, target: str) -> None:
        """Link-local and metadata endpoints must be blocked."""
        with pytest.raises(BlockedTargetError) as exc_info:
            await assert_public_target(target)
        assert exc_info.value.reason_code == "NON_PUBLIC_ADDRESS"


class TestCGNAT:
    """Test CGNAT range (100.64.0.0/10)."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "target",
        [
            "http://100.64.0.0",
            "http://100.64.0.1",
            "http://100.127.255.255",
            "http://100.100.100.100",
            "http://100.64.1.1:8080",
        ],
    )
    async def test_cgnat_blocked(self, target: str) -> None:
        """CGNAT range must be blocked."""
        with pytest.raises(BlockedTargetError) as exc_info:
            await assert_public_target(target)
        assert exc_info.value.reason_code == "NON_PUBLIC_ADDRESS"


class TestSpecialAddresses:
    """Test special and reserved addresses."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "target",
        [
            # 0.0.0.0 (unspecified)
            "http://0.0.0.0",
            "http://0.0.0.0:8080",
            # IPv6 unspecified
            "http://[::]",
            "http://[0:0:0:0:0:0:0:0]",
            # Multicast addresses
            "http://224.0.0.1",  # IPv4 multicast
            "http://239.255.255.255",
            "http://[ff00::1]",  # IPv6 multicast
            "http://[ff02::1]",
            # Broadcast
            "http://255.255.255.255",
            # Reserved ranges
            "http://240.0.0.1",  # Future use (240.0.0.0/4)
            "http://0.255.255.255",  # 0.0.0.0/8 reserved
        ],
    )
    async def test_special_addresses_blocked(self, target: str) -> None:
        """Special and reserved addresses must be blocked."""
        with pytest.raises(BlockedTargetError) as exc_info:
            await assert_public_target(target)
        assert exc_info.value.reason_code == "NON_PUBLIC_ADDRESS"


class TestLocalhostAliases:
    """Test localhost hostname variants."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "target",
        [
            "http://localhost",
            "http://localhost:8080",
            "https://localhost",
            "http://localhost.localdomain",
            "http://LOCALHOST",  # case variations
            "http://LocalHost",
        ],
    )
    async def test_localhost_hostnames_blocked(self, target: str) -> None:
        """Localhost hostnames must be blocked."""
        with pytest.raises(BlockedTargetError) as exc_info:
            await assert_public_target(target)
        assert exc_info.value.reason_code == "DENIED_HOSTNAME"


class TestDeniedHostnames:
    """Test .local, .internal, .localhost TLDs."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "target",
        [
            "http://something.localhost",
            "http://api.localhost",
            "http://test.internal",
            "http://admin.internal",
            "http://service.local",
            "http://database.local",
            "http://redis.local",
            "http://postgres",  # from denylist
            "http://redis",
            "http://backend",
            "http://worker",
        ],
    )
    async def test_denied_hostnames_blocked(self, target: str) -> None:
        """Denied hostnames and TLDs must be blocked."""
        with pytest.raises(BlockedTargetError) as exc_info:
            await assert_public_target(target)
        assert exc_info.value.reason_code == "DENIED_HOSTNAME"


class TestCredentialsInURL:
    """Test URLs with embedded credentials."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "target",
        [
            "http://user:pass@example.com",
            "http://admin:secret@example.com",
            "https://user@example.com",
            "http://:password@example.com",
            "http://user:@example.com",
        ],
    )
    async def test_credentials_blocked(self, target: str) -> None:
        """URLs with embedded credentials must be blocked."""
        with pytest.raises(BlockedTargetError) as exc_info:
            await assert_public_target(target)
        assert exc_info.value.reason_code == "INVALID_TARGET"


class TestUnsupportedSchemes:
    """Test non-HTTP(S) schemes."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "target",
        [
            "file:///etc/passwd",
            "file://localhost/etc/passwd",
            "ftp://example.com/file.txt",
            "ftps://example.com",
            "gopher://example.com",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "mailto:user@example.com",
            "ssh://example.com",
            "telnet://example.com",
            "ldap://example.com",
            "dict://example.com",
        ],
    )
    async def test_unsupported_schemes_blocked(self, target: str) -> None:
        """Non-HTTP(S) schemes must be blocked."""
        with pytest.raises(BlockedTargetError) as exc_info:
            await assert_public_target(target)
        assert exc_info.value.reason_code == "UNSUPPORTED_SCHEME"


class TestDNSResolvingToPrivate:
    """Test DNS names that resolve to private IPs using a fake resolver."""

    @pytest.mark.asyncio
    async def test_hostname_resolves_to_loopback(self) -> None:
        """Hostname resolving to 127.0.0.1 must be blocked."""
        mock_resolver = MagicMock(spec=dns.asyncresolver.Resolver)

        # Mock A record returning 127.0.0.1
        a_answer = MagicMock()
        a_record = MagicMock()
        a_record.address = "127.0.0.1"
        a_answer.__iter__ = MagicMock(return_value=iter([a_record]))
        
        # Mock AAAA record returning nothing
        mock_resolver.resolve = AsyncMock(side_effect=[a_answer, dns.resolver.NoAnswer()])

        with pytest.raises(BlockedTargetError) as exc_info:
            await assert_public_target("http://evil.example.com", resolver=mock_resolver)
        assert exc_info.value.reason_code == "NON_PUBLIC_ADDRESS"

    @pytest.mark.asyncio
    async def test_hostname_resolves_to_private_ipv4(self) -> None:
        """Hostname resolving to 192.168.1.1 must be blocked."""
        mock_resolver = MagicMock(spec=dns.asyncresolver.Resolver)

        a_answer = MagicMock()
        a_record = MagicMock()
        a_record.address = "192.168.1.1"
        a_answer.__iter__ = MagicMock(return_value=iter([a_record]))
        
        mock_resolver.resolve = AsyncMock(side_effect=[a_answer, dns.resolver.NoAnswer()])

        with pytest.raises(BlockedTargetError) as exc_info:
            await assert_public_target("http://internal.example.com", resolver=mock_resolver)
        assert exc_info.value.reason_code == "NON_PUBLIC_ADDRESS"

    @pytest.mark.asyncio
    async def test_hostname_resolves_to_metadata_ip(self) -> None:
        """Hostname resolving to cloud metadata IP must be blocked."""
        mock_resolver = MagicMock(spec=dns.asyncresolver.Resolver)

        a_answer = MagicMock()
        a_record = MagicMock()
        a_record.address = "169.254.169.254"
        a_answer.__iter__ = MagicMock(return_value=iter([a_record]))
        
        mock_resolver.resolve = AsyncMock(side_effect=[a_answer, dns.resolver.NoAnswer()])

        with pytest.raises(BlockedTargetError) as exc_info:
            await assert_public_target("http://metadata.example.com", resolver=mock_resolver)
        assert exc_info.value.reason_code == "NON_PUBLIC_ADDRESS"

    @pytest.mark.asyncio
    async def test_hostname_resolves_to_private_ipv6(self) -> None:
        """Hostname resolving to private IPv6 must be blocked."""
        mock_resolver = MagicMock(spec=dns.asyncresolver.Resolver)

        aaaa_answer = MagicMock()
        aaaa_record = MagicMock()
        aaaa_record.address = "fc00::1"
        aaaa_answer.__iter__ = MagicMock(return_value=iter([aaaa_record]))
        
        mock_resolver.resolve = AsyncMock(side_effect=[dns.resolver.NoAnswer(), aaaa_answer])

        with pytest.raises(BlockedTargetError) as exc_info:
            await assert_public_target("http://ipv6private.example.com", resolver=mock_resolver)
        assert exc_info.value.reason_code == "NON_PUBLIC_ADDRESS"

    @pytest.mark.asyncio
    async def test_hostname_resolves_to_mixed_public_private(self) -> None:
        """Hostname resolving to both public and private IPs must be blocked."""
        mock_resolver = MagicMock(spec=dns.asyncresolver.Resolver)

        a_answer = MagicMock()
        a_record_public = MagicMock()
        a_record_public.address = "1.1.1.1"
        a_record_private = MagicMock()
        a_record_private.address = "10.0.0.1"
        a_answer.__iter__ = MagicMock(return_value=iter([a_record_public, a_record_private]))
        
        mock_resolver.resolve = AsyncMock(side_effect=[a_answer, dns.resolver.NoAnswer()])

        with pytest.raises(BlockedTargetError) as exc_info:
            await assert_public_target("http://mixed.example.com", resolver=mock_resolver)
        assert exc_info.value.reason_code == "NON_PUBLIC_ADDRESS"


class TestIPv6ZoneIDs:
    """Test IPv6 addresses with zone identifiers."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "target",
        [
            "http://[fe80::1%lo0]",
            "http://[fe80::1%25lo0]",  # URL-encoded %
            "http://[fe80::1%eth0]",
            "http://[fe80::1%1]",  # numeric zone
        ],
    )
    async def test_ipv6_zone_ids_blocked(self, target: str) -> None:
        """IPv6 link-local with zone IDs must be blocked."""
        with pytest.raises(BlockedTargetError) as exc_info:
            await assert_public_target(target)
        # Will fail during parsing or be caught as link-local
        assert exc_info.value.reason_code in ("NON_PUBLIC_ADDRESS", "INVALID_TARGET")


class TestValidPublicTargets:
    """Verify that legitimate public targets are allowed."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "target,expected_hostname",
        [
            ("http://example.com", "example.com"),
            ("https://google.com", "google.com"),
            ("http://1.1.1.1", "1.1.1.1"),
            ("http://8.8.8.8:80", "8.8.8.8"),
            ("https://www.wikipedia.org", "www.wikipedia.org"),
            ("http://[2606:4700:4700::1111]", "2606:4700:4700::1111"),  # Cloudflare DNS
        ],
    )
    async def test_public_targets_allowed(self, target: str, expected_hostname: str) -> None:
        """Public targets should pass validation."""
        mock_resolver = MagicMock(spec=dns.asyncresolver.Resolver)
        
        # For IP addresses, no DNS resolution happens
        # For hostnames, mock a public IP response
        if not any(char in target for char in ['[', ']']) and not target.split('://')[1].split(':')[0].replace('.', '').isdigit():
            a_answer = MagicMock()
            a_record = MagicMock()
            a_record.address = "1.1.1.1"  # Public IP
            a_answer.__iter__ = MagicMock(return_value=iter([a_record]))
            mock_resolver.resolve = AsyncMock(side_effect=[a_answer, dns.resolver.NoAnswer()])
            
            result = await assert_public_target(target, resolver=mock_resolver)
        else:
            result = await assert_public_target(target)
        
        assert result.hostname == expected_hostname
        assert result.scheme in ("http", "https")
        assert len(result.addresses) > 0


class TestEdgeCases:
    """Test edge cases and malformed inputs."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "target",
        [
            "",
            "   ",
            "not-a-url",
            "http://",
            "http://:",
            "http:// space.com",
            "http://host with spaces.com",
        ],
    )
    async def test_invalid_targets(self, target: str) -> None:
        """Invalid or malformed targets must be rejected."""
        with pytest.raises(BlockedTargetError) as exc_info:
            await assert_public_target(target)
        # Accept either INVALID_TARGET or DNS_RESOLUTION_FAILED
        # (e.g., "not-a-url" looks like a hostname and fails DNS)
        assert exc_info.value.reason_code in ("INVALID_TARGET", "DNS_RESOLUTION_FAILED")

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "target",
        [
            "http://example.com:0",
            "http://example.com:65536",
            "http://example.com:99999",
            "http://example.com:-1",
        ],
    )
    async def test_invalid_ports(self, target: str) -> None:
        """Invalid port numbers must be rejected."""
        with pytest.raises(BlockedTargetError) as exc_info:
            await assert_public_target(target)
        assert exc_info.value.reason_code == "INVALID_TARGET"


# Test count verification
def test_ssrf_test_count() -> None:
    """Verify we have at least 50 SSRF test cases as required."""
    import inspect
    
    test_count = 0
    for name, obj in globals().items():
        if name.startswith('Test') and inspect.isclass(obj):
            for method_name in dir(obj):
                if method_name.startswith('test_'):
                    method = getattr(obj, method_name)
                    # Count parametrized tests
                    if hasattr(method, 'pytestmark'):
                        for mark in method.pytestmark:
                            if mark.name == 'parametrize':
                                # Get the number of parameter sets
                                test_count += len(mark.args[1])
                                break
                    else:
                        test_count += 1
    
    assert test_count >= 50, f"SSRF suite must have at least 50 tests, found {test_count}"
    print(f"✓ SSRF test suite contains {test_count} test cases")
