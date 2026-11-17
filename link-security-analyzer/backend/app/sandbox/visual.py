"""Visual brand matching using perceptual hashing.

Compares screenshot pHash/dHash with brand references to detect lookalike pages.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from io import BytesIO
from typing import Any, Optional

try:
    import imagehash
    from PIL import Image
except ImportError:
    imagehash = None  # type: ignore
    Image = None  # type: ignore


@dataclass
class BrandMatch:
    """Result of comparing a screenshot to brand references."""

    brand_id: str
    brand_name: str
    distance: int
    reference_url: str
    reference_type: str  # 'phash', 'dhash', 'favicon'
    threshold: int


@dataclass
class VisualMatchResult:
    """Result of visual brand matching."""

    matched: bool
    best_match: Optional[BrandMatch] = None
    all_matches: list[BrandMatch] = None  # type: ignore
    skipped_reason: Optional[str] = None


def compute_hashes(
    screenshot_png: bytes,
    favicon_bytes: Optional[bytes] = None,
) -> dict[str, Any]:
    """Compute perceptual hashes for screenshot and favicon.

    Args:
        screenshot_png: Screenshot PNG bytes
        favicon_bytes: Optional favicon bytes

    Returns:
        Dict with phash_hex, dhash_hex, favicon_sha256, favicon_phash_hex (if decodable)
    """
    if imagehash is None or Image is None:
        return {'error': 'imagehash or PIL not available'}

    hashes: dict[str, Any] = {}

    # Screenshot hashes
    try:
        img = Image.open(BytesIO(screenshot_png))

        # pHash (perceptual hash) - 64 bits, resistant to minor changes
        phash = imagehash.phash(img, hash_size=8)  # 8x8 = 64 bits
        hashes['phash_hex'] = str(phash)

        # dHash (difference hash) - 64 bits, detects gradients
        dhash = imagehash.dhash(img, hash_size=8)
        hashes['dhash_hex'] = str(dhash)

        # Upper viewport crop (for pages with dynamic lower content)
        width, height = img.size
        upper_half = img.crop((0, 0, width, height // 2))
        upper_phash = imagehash.phash(upper_half, hash_size=8)
        hashes['upper_phash_hex'] = str(upper_phash)

    except Exception as error:  # noqa: BLE001
        hashes['screenshot_error'] = str(error)

    # Initialize favicon fields to None if not provided
    if not favicon_bytes:
        hashes['favicon_sha256'] = None
        hashes['favicon_phash_hex'] = None

    # Favicon hashes
    if favicon_bytes:
        # SHA-256 for exact match
        hashes['favicon_sha256'] = hashlib.sha256(favicon_bytes).hexdigest()

        # Try to decode as image and compute pHash
        try:
            fav_img = Image.open(BytesIO(favicon_bytes))
            fav_phash = imagehash.phash(fav_img, hash_size=8)
            hashes['favicon_phash_hex'] = str(fav_phash)
        except Exception:  # noqa: BLE001
            # Favicon not decodable as image (or corrupted)
            hashes['favicon_phash_hex'] = None

    return hashes


def hamming_distance(hash1: str, hash2: str) -> int:
    """Compute Hamming distance between two hex hash strings.

    Args:
        hash1: First hash (hex string)
        hash2: Second hash (hex string)

    Returns:
        Number of differing bits
    """
    if not hash1 or not hash2:
        return 64  # Maximum distance if either is missing

    try:
        # Convert hex to int, XOR, count bits
        int1 = int(hash1, 16)
        int2 = int(hash2, 16)
        xor = int1 ^ int2
        # Python 3.10+ has int.bit_count(), for 3.9 use bin().count('1')
        return bin(xor).count('1')
    except (ValueError, AttributeError):
        return 64


def match_brands(
    screenshot_hashes: dict[str, Any],
    brand_references: list[dict[str, Any]],
    registrable_domain: Optional[str],
    phash_threshold: int = 10,
    favicon_threshold: int = 8,
) -> VisualMatchResult:
    """Match screenshot against brand references.

    Args:
        screenshot_hashes: Dict with phash_hex, dhash_hex, etc from compute_hashes()
        brand_references: List of brand reference dicts from DB
        registrable_domain: Page's registrable domain (to check if official)
        phash_threshold: Max Hamming distance for pHash match (default 10 of 64 bits)
        favicon_threshold: Max Hamming distance for favicon match (default 8)

    Returns:
        VisualMatchResult with best match and all matches below threshold
    """
    if imagehash is None:
        return VisualMatchResult(
            matched=False,
            skipped_reason='imagehash_not_available'
        )

    if 'phash_hex' not in screenshot_hashes:
        return VisualMatchResult(
            matched=False,
            skipped_reason='screenshot_hash_failed'
        )

    if not brand_references:
        return VisualMatchResult(
            matched=False,
            all_matches=[],
            skipped_reason='no_brand_references'
        )

    page_phash = screenshot_hashes.get('phash_hex', '')
    page_dhash = screenshot_hashes.get('dhash_hex', '')
    page_upper_phash = screenshot_hashes.get('upper_phash_hex', '')
    page_favicon_phash = screenshot_hashes.get('favicon_phash_hex')
    page_favicon_sha256 = screenshot_hashes.get('favicon_sha256')

    matches: list[BrandMatch] = []

    for ref in brand_references:
        brand_id = ref.get('brand_id', '')
        brand_name = ref.get('brand_name', '')
        official_domains = ref.get('official_domains', [])
        ref_url = ref.get('source_url', '')

        # Skip if page domain is official
        if registrable_domain and any(
            registrable_domain == official or registrable_domain.endswith('.' + official)
            for official in official_domains
        ):
            return VisualMatchResult(
                matched=False,
                all_matches=[],
                skipped_reason='page_on_official_domain'
            )

        # Compare pHash
        ref_phash = ref.get('phash_hex')
        if ref_phash:
            distance = hamming_distance(page_phash, ref_phash)
            if distance <= phash_threshold:
                matches.append(BrandMatch(
                    brand_id=brand_id,
                    brand_name=brand_name,
                    distance=distance,
                    reference_url=ref_url,
                    reference_type='phash',
                    threshold=phash_threshold,
                ))

        # Compare dHash (secondary check)
        ref_dhash = ref.get('dhash_hex')
        if ref_dhash and not matches:  # Only if phash didn't match
            distance = hamming_distance(page_dhash, ref_dhash)
            if distance <= phash_threshold:
                matches.append(BrandMatch(
                    brand_id=brand_id,
                    brand_name=brand_name,
                    distance=distance,
                    reference_url=ref_url,
                    reference_type='dhash',
                    threshold=phash_threshold,
                ))

        # Compare upper viewport pHash (for pages with dynamic lower sections)
        ref_upper_phash = ref.get('upper_phash_hex')
        if ref_upper_phash and not matches:
            distance = hamming_distance(page_upper_phash, ref_upper_phash)
            if distance <= phash_threshold:
                matches.append(BrandMatch(
                    brand_id=brand_id,
                    brand_name=brand_name,
                    distance=distance,
                    reference_url=ref_url,
                    reference_type='upper_phash',
                    threshold=phash_threshold,
                ))

        # Compare favicon
        if page_favicon_sha256 and page_favicon_phash:
            # Exact SHA-256 match
            ref_favicon_sha256 = ref.get('favicon_sha256')
            if ref_favicon_sha256 and page_favicon_sha256 == ref_favicon_sha256:
                matches.append(BrandMatch(
                    brand_id=brand_id,
                    brand_name=brand_name,
                    distance=0,
                    reference_url=ref_url,
                    reference_type='favicon_exact',
                    threshold=0,
                ))

            # Favicon pHash match (for resized/recompressed favicons)
            ref_favicon_phash = ref.get('favicon_phash_hex')
            if ref_favicon_phash:
                distance = hamming_distance(page_favicon_phash, ref_favicon_phash)
                if distance <= favicon_threshold:
                    matches.append(BrandMatch(
                        brand_id=brand_id,
                        brand_name=brand_name,
                        distance=distance,
                        reference_url=ref_url,
                        reference_type='favicon_phash',
                        threshold=favicon_threshold,
                    ))

    # Deduplicate matches by (brand_id, reference_type), keep best (lowest distance)
    unique_matches: dict[tuple[str, str], BrandMatch] = {}
    for match in matches:
        key = (match.brand_id, match.reference_type)
        if key not in unique_matches or match.distance < unique_matches[key].distance:
            unique_matches[key] = match

    final_matches = sorted(unique_matches.values(), key=lambda m: m.distance)

    if final_matches:
        return VisualMatchResult(
            matched=True,
            best_match=final_matches[0],
            all_matches=final_matches,
        )

    return VisualMatchResult(
        matched=False,
        all_matches=[],
    )


def generate_signals(
    match_result: VisualMatchResult,
    has_credential_fields: bool = False,
) -> list[dict[str, Any]]:
    """Generate signals from visual match result.

    Args:
        match_result: Result from match_brands()
        has_credential_fields: Whether page has password/OTP fields (for combination rule)

    Returns:
        List of signal dicts
    """
    signals = []

    if not match_result.matched or not match_result.best_match:
        return signals

    best = match_result.best_match

    # Main visual brand match signal
    if best.reference_type in {'phash', 'dhash', 'upper_phash'}:
        signals.append({
            'id': 'VISUAL_BRAND_MATCH',
            'points': 40,
            'severity': 'high',
            'explanation': f"Page layout resembles {best.brand_name} (distance: {best.distance} bits)",
            'evidence': {
                'brand_name': best.brand_name,
                'distance': best.distance,
                'threshold': best.threshold,
                'match_type': best.reference_type,
            },
        })

    # Favicon match signal
    elif best.reference_type in {'favicon_exact', 'favicon_phash'}:
        signals.append({
            'id': 'FAVICON_BRAND_MATCH',
            'points': 20,
            'severity': 'medium',
            'explanation': f"Favicon matches {best.brand_name}",
            'evidence': {
                'brand_name': best.brand_name,
                'distance': best.distance if best.reference_type == 'favicon_phash' else 0,
                'match_type': best.reference_type,
            },
        })

    # Combination rule: brand lookalike + credential fields
    # (This is also in DOM analyzer; here we add it if only visual match triggered it)
    if has_credential_fields and any(s['id'] == 'VISUAL_BRAND_MATCH' for s in signals):
        signals.append({
            'id': 'BRAND_LOOKALIKE_ON_FOREIGN_DOMAIN',
            'points': 25,
            'severity': 'high',
            'explanation': 'Page impersonates a brand and asks for credentials',
            'evidence': {'brand_name': best.brand_name},
        })

    return signals
