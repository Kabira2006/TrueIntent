"""Tests for visual brand matching."""

from __future__ import annotations

import io
from typing import TYPE_CHECKING

import pytest

# NOTE: Most tests in this file require imagehash and PIL to be installed.
# Without these libraries, match_brands() returns early with imagehash_not_available.
# These tests are expected to pass in the Docker environment where imagehash is installed.
# Local failures without imagehash are acceptable.

if TYPE_CHECKING:
    from PIL import Image
    import imagehash


@pytest.fixture
def mock_imagehash(monkeypatch):
    """Mock imagehash to avoid PIL dependency in CI."""

    class MockHash:
        def __init__(self, value: int):
            self.value = value

        def __str__(self) -> str:
            return f"{self.value:016x}"

        def __sub__(self, other):
            # XOR to count differing bits (Hamming distance)
            diff = self.value ^ other.value
            return bin(diff).count("1")

    class MockImageHash:
        @staticmethod
        def phash(img, hash_size=8):
            # Deterministic hash based on image size
            width, height = img.size
            return MockHash((width * 1000 + height) % (2**64))

        @staticmethod
        def dhash(img, hash_size=8):
            width, height = img.size
            return MockHash((width * 2000 + height) % (2**64))

    class MockImage:
        @staticmethod
        def open(fp):
            # Return mock image with fixed size
            if hasattr(fp, "read"):
                fp.read()  # consume bytes
            mock_img = type("MockPILImage", (), {"size": (800, 600), "crop": lambda self, box: self})()
            return mock_img

    try:
        import imagehash as real_imagehash
        import PIL.Image as real_Image
        # If imports succeed, we have real libraries, use them
    except ImportError:
        # Mock only if libraries not available
        monkeypatch.setattr("app.sandbox.visual.imagehash", MockImageHash)
        monkeypatch.setattr("app.sandbox.visual.Image", MockImage)


def test_compute_hashes_deterministic(mock_imagehash):
    """Hashes of the same screenshot should be identical."""
    from app.sandbox.visual import compute_hashes

    # Fake PNG bytes (valid PNG header)
    fake_png = (
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\rIHDR\x00\x00\x01\x00\x00\x00\x00\x80\x08\x02\x00\x00\x00"
        b"\x00" * 100  # padding
    )

    result1 = compute_hashes(fake_png)
    result2 = compute_hashes(fake_png)

    assert result1["phash_hex"] == result2["phash_hex"]
    assert result1["dhash_hex"] == result2["dhash_hex"]
    assert result1["upper_phash_hex"] == result2["upper_phash_hex"]


def test_compute_hashes_with_favicon(mock_imagehash):
    """Favicon hashes computed when favicon_bytes provided."""
    from app.sandbox.visual import compute_hashes

    fake_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    fake_favicon = b"\x89PNG\r\n\x1a\n" + b"\xFF" * 50

    result = compute_hashes(fake_png, favicon_bytes=fake_favicon)

    assert "favicon_sha256" in result
    assert "favicon_phash_hex" in result
    assert len(result["favicon_sha256"]) == 64  # SHA-256 hex is 64 chars
    assert result["favicon_phash_hex"] is not None


def test_compute_hashes_no_favicon(mock_imagehash):
    """Favicon fields None when no favicon provided."""
    from app.sandbox.visual import compute_hashes

    fake_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100

    result = compute_hashes(fake_png)

    assert result["favicon_sha256"] is None
    assert result["favicon_phash_hex"] is None


def test_hamming_distance():
    """Hamming distance counts differing bits."""
    from app.sandbox.visual import hamming_distance

    # Identical hashes: distance 0
    assert hamming_distance("0000000000000000", "0000000000000000") == 0

    # 1 bit different: distance 1
    assert hamming_distance("0000000000000000", "0000000000000001") == 1

    # All bits different: distance 64
    assert hamming_distance("0000000000000000", "ffffffffffffffff") == 64

    # Mixed: 4 bits different (0x5 = 0101, 0xA = 1010)
    assert hamming_distance("0000000000000005", "000000000000000a") == 4


def test_match_brands_no_references():
    """No match when brand_references is empty."""
    from app.sandbox.visual import match_brands

    screenshot_hashes = {
        "phash_hex": "0123456789abcdef",
        "dhash_hex": "fedcba9876543210",
        "upper_phash_hex": "0011223344556677",
        "favicon_sha256": None,
        "favicon_phash_hex": None,
    }

    result = match_brands(screenshot_hashes, [], "example.com")

    assert not result.matched
    assert result.best_match is None
    # all_matches is either [] or None (depends on imagehash availability)
    assert result.all_matches == [] or result.all_matches is None


def test_match_brands_official_domain_exempt():
    """No match when page is on official brand domain."""
    from app.sandbox.visual import match_brands

    screenshot_hashes = {
        "phash_hex": "0123456789abcdef",
        "dhash_hex": "fedcba9876543210",
        "upper_phash_hex": "0011223344556677",
        "favicon_sha256": None,
        "favicon_phash_hex": None,
    }

    brand_refs = [
        {
            "brand_id": "sbi",
            "brand_name": "State Bank of India",
            "official_domains": ["onlinesbi.sbi", "retail.onlinesbi.sbi"],
            "phash_hex": "0123456789abcdef",  # exact match
            "dhash_hex": "fedcba9876543210",
            "upper_phash_hex": "0011223344556677",
            "reference_url": "https://retail.onlinesbi.sbi/login",
            "reference_type": "login",
        }
    ]

    # Page is on official domain → no match (exempt)
    result = match_brands(screenshot_hashes, brand_refs, "onlinesbi.sbi")

    assert not result.matched
    assert result.skipped_reason == "page_on_official_domain"


def test_match_brands_exact_phash_match():
    """Exact pHash match on foreign domain triggers match."""
    from app.sandbox.visual import match_brands

    screenshot_hashes = {
        "phash_hex": "0123456789abcdef",
        "dhash_hex": "fedcba9876543210",
        "upper_phash_hex": "0011223344556677",
        "favicon_sha256": None,
        "favicon_phash_hex": None,
    }

    brand_refs = [
        {
            "brand_id": "sbi",
            "brand_name": "State Bank of India",
            "official_domains": ["onlinesbi.sbi"],
            "phash_hex": "0123456789abcdef",  # exact match (distance 0)
            "dhash_hex": "aaaaaaaabbbbbbbb",
            "upper_phash_hex": "ccccccccdddddddd",
            "reference_url": "https://retail.onlinesbi.sbi/login",
            "reference_type": "login",
        }
    ]

    result = match_brands(screenshot_hashes, brand_refs, "sbi-secure.xyz")

    assert result.matched
    assert result.best_match is not None
    assert result.best_match.brand_id == "sbi"
    assert result.best_match.distance == 0
    assert result.best_match.reference_type == "phash"


def test_match_brands_within_threshold():
    """Match when distance within threshold."""
    from app.sandbox.visual import match_brands

    # Hashes differ by 5 bits
    screenshot_hashes = {
        "phash_hex": "0000000000000000",
        "dhash_hex": "0000000000000000",
        "upper_phash_hex": "0000000000000000",
        "favicon_sha256": None,
        "favicon_phash_hex": None,
    }

    brand_refs = [
        {
            "brand_id": "hdfc",
            "brand_name": "HDFC Bank",
            "official_domains": ["netbanking.hdfcbank.com"],
            "phash_hex": "000000000000001f",  # 5 bits set (11111)
            "dhash_hex": "0000000000000000",
            "upper_phash_hex": "0000000000000000",
            "reference_url": "https://netbanking.hdfcbank.com/",
            "reference_type": "homepage",
        }
    ]

    # Default threshold is 10, distance 5 should match
    result = match_brands(screenshot_hashes, brand_refs, "hdfc-bank-secure.com", phash_threshold=10)

    assert result.matched
    assert result.best_match.distance == 5


def test_match_brands_exceeds_threshold():
    """No match when distance exceeds threshold."""
    from app.sandbox.visual import match_brands

    screenshot_hashes = {
        "phash_hex": "0000000000000000",
        "dhash_hex": "0000000000000000",
        "upper_phash_hex": "0000000000000000",
        "favicon_sha256": None,
        "favicon_phash_hex": None,
    }

    brand_refs = [
        {
            "brand_id": "icici",
            "brand_name": "ICICI Bank",
            "official_domains": ["icicibank.com"],
            "phash_hex": "00000000000007ff",  # 11 bits set
            "dhash_hex": "0000000000000000",
            "upper_phash_hex": "0000000000000000",
            "reference_url": "https://www.icicibank.com/",
            "reference_type": "login",
        }
    ]

    # Distance 11 > threshold 10
    result = match_brands(screenshot_hashes, brand_refs, "icici-secure.net", phash_threshold=10)

    assert not result.matched


def test_match_brands_favicon_exact_match():
    """Exact favicon SHA-256 match triggers match."""
    from app.sandbox.visual import match_brands

    screenshot_hashes = {
        "phash_hex": "aaaaaaaaaaaaaaaa",
        "dhash_hex": "bbbbbbbbbbbbbbbb",
        "upper_phash_hex": "cccccccccccccccc",
        "favicon_sha256": "abc123" * 10 + "abcd",  # 64 chars
        "favicon_phash_hex": "dddddddddddddddd",
    }

    brand_refs = [
        {
            "brand_id": "amazon",
            "brand_name": "Amazon India",
            "official_domains": ["amazon.in"],
            "phash_hex": "0000000000000000",  # different
            "dhash_hex": "0000000000000000",
            "upper_phash_hex": "0000000000000000",
            "favicon_sha256": "abc123" * 10 + "abcd",  # exact match
            "favicon_phash_hex": "dddddddddddddddd",
            "reference_url": "https://www.amazon.in/",
            "reference_type": "homepage",
        }
    ]

    result = match_brands(screenshot_hashes, brand_refs, "amazon-deals.xyz")

    assert result.matched
    assert result.best_match.reference_type == "favicon"
    assert result.best_match.distance == 0


def test_match_brands_multiple_refs_best_match():
    """Returns closest match when multiple refs match."""
    from app.sandbox.visual import match_brands

    screenshot_hashes = {
        "phash_hex": "0000000000000000",
        "dhash_hex": "0000000000000000",
        "upper_phash_hex": "0000000000000000",
        "favicon_sha256": None,
        "favicon_phash_hex": None,
    }

    brand_refs = [
        {
            "brand_id": "flipkart",
            "brand_name": "Flipkart",
            "official_domains": ["flipkart.com"],
            "phash_hex": "000000000000000f",  # distance 4
            "dhash_hex": "0000000000000000",
            "upper_phash_hex": "0000000000000000",
            "reference_url": "https://www.flipkart.com/",
            "reference_type": "homepage",
        },
        {
            "brand_id": "flipkart",
            "brand_name": "Flipkart",
            "official_domains": ["flipkart.com"],
            "phash_hex": "0000000000000003",  # distance 2 (better)
            "dhash_hex": "0000000000000000",
            "upper_phash_hex": "0000000000000000",
            "reference_url": "https://www.flipkart.com/login",
            "reference_type": "login",
        },
    ]

    result = match_brands(screenshot_hashes, brand_refs, "flipkart-sale.com", phash_threshold=10)

    assert result.matched
    assert result.best_match.distance == 2
    assert len(result.all_matches) == 2


def test_generate_signals_visual_match():
    """VISUAL_BRAND_MATCH signal generated for screenshot match."""
    from app.sandbox.visual import generate_signals, BrandMatch, VisualMatchResult

    match_result = VisualMatchResult(
        matched=True,
        best_match=BrandMatch(
            brand_id="paytm",
            brand_name="Paytm",
            distance=3,
            reference_url="https://paytm.com/",
            reference_type="phash",
            threshold=10,
        ),
        all_matches=[],
    )

    signals = generate_signals(match_result, has_credential_fields=False)

    assert len(signals) == 1
    assert signals[0]["id"] == "VISUAL_BRAND_MATCH"
    assert signals[0]["points"] == 40
    assert signals[0]["severity"] == "high"
    assert "Paytm" in signals[0]["explanation"]
    assert signals[0]["evidence"]["brand_name"] == "Paytm"
    assert signals[0]["evidence"]["distance"] == 3


def test_generate_signals_favicon_match():
    """FAVICON_BRAND_MATCH signal generated for favicon match."""
    from app.sandbox.visual import generate_signals, BrandMatch, VisualMatchResult

    match_result = VisualMatchResult(
        matched=True,
        best_match=BrandMatch(
            brand_id="gpay",
            brand_name="Google Pay",
            distance=0,
            reference_url="https://pay.google.com/",
            reference_type="favicon",
            threshold=8,
        ),
        all_matches=[],
    )

    signals = generate_signals(match_result, has_credential_fields=False)

    assert len(signals) == 1
    assert signals[0]["id"] == "FAVICON_BRAND_MATCH"
    assert signals[0]["points"] == 20
    assert "favicon" in signals[0]["explanation"].lower()


def test_generate_signals_brand_lookalike_combo():
    """BRAND_LOOKALIKE_ON_FOREIGN_DOMAIN combo signal when credentials present."""
    from app.sandbox.visual import generate_signals, BrandMatch, VisualMatchResult

    match_result = VisualMatchResult(
        matched=True,
        best_match=BrandMatch(
            brand_id="axis",
            brand_name="Axis Bank",
            distance=5,
            reference_url="https://axisbank.com/",
            reference_type="phash",
            threshold=10,
        ),
        all_matches=[],
    )

    signals = generate_signals(match_result, has_credential_fields=True)

    assert len(signals) == 2
    signal_ids = {s["id"] for s in signals}
    assert "VISUAL_BRAND_MATCH" in signal_ids
    assert "BRAND_LOOKALIKE_ON_FOREIGN_DOMAIN" in signal_ids

    combo_signal = next(s for s in signals if s["id"] == "BRAND_LOOKALIKE_ON_FOREIGN_DOMAIN")
    assert combo_signal["points"] == 25
    assert combo_signal["severity"] == "high"


def test_generate_signals_no_match():
    """Empty signal list when no match."""
    from app.sandbox.visual import generate_signals, VisualMatchResult

    match_result = VisualMatchResult(matched=False)

    signals = generate_signals(match_result, has_credential_fields=False)

    assert signals == []


def test_compute_hashes_missing_imagehash():
    """Returns error when imagehash not available."""
    from app.sandbox import visual

    # Temporarily set imagehash to None
    original = visual.imagehash
    visual.imagehash = None

    try:
        result = visual.compute_hashes(b"fake")
        assert "error" in result
        assert "imagehash" in result["error"].lower() or "pil" in result["error"].lower()
    finally:
        visual.imagehash = original
