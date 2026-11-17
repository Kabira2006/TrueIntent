"""Build brand reference hashes by visiting login pages.

Visits each brand's login URLs with Playwright, captures screenshots,
computes perceptual hashes, and stores in brand_references table + exports to JSON.
"""

import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.models import BrandReference
from app.db.session import get_sync_session
from app.sandbox.browser import visit
from app.sandbox.visual import compute_hashes


async def capture_brand_reference(
    brand_id: str,
    brand_name: str,
    url: str,
    official_domains: list[str],
    reference_type: str = 'login',
) -> dict:
    """Capture a single brand reference.

    Args:
        brand_id: Brand identifier
        brand_name: Display name
        url: URL to capture
        official_domains: List of official domains
        reference_type: 'login', 'homepage', 'mobile', etc.

    Returns:
        Dict with brand info + hashes + capture_quality
    """
    print(f"Capturing {brand_name} ({reference_type}): {url}")

    try:
        # Visit with Phase 5 sandbox
        result = await visit(url, budget_s=15.0)

        if result.errors:
            print(f"  ⚠️  Errors: {result.errors}")
            return {
                'brand_id': brand_id,
                'brand_name': brand_name,
                'official_domains': official_domains,
                'source_url': url,
                'reference_type': reference_type,
                'capture_quality': 'failed',
                'capture_error': '; '.join(result.errors),
                'captured_at': datetime.now(timezone.utc).isoformat(),
            }

        if not result.screenshot_png:
            print(f"  ⚠️  No screenshot captured")
            return {
                'brand_id': brand_id,
                'brand_name': brand_name,
                'official_domains': official_domains,
                'source_url': url,
                'reference_type': reference_type,
                'capture_quality': 'failed',
                'capture_error': 'no_screenshot',
                'captured_at': datetime.now(timezone.utc).isoformat(),
            }

        # Compute hashes
        hashes = compute_hashes(result.screenshot_png, result.favicon_bytes)

        if 'error' in hashes or 'screenshot_error' in hashes:
            print(f"  ⚠️  Hash computation failed: {hashes.get('error') or hashes.get('screenshot_error')}")
            capture_quality = 'poor'
        else:
            print(f"  ✓ Captured: phash={hashes.get('phash_hex', 'N/A')[:16]}...")
            capture_quality = 'good'

        # Build reference dict
        ref = {
            'brand_id': brand_id,
            'brand_name': brand_name,
            'official_domains': official_domains,
            'source_url': url,
            'final_url': result.final_url,
            'reference_type': reference_type,
            'capture_quality': capture_quality,
            'captured_at': datetime.now(timezone.utc).isoformat(),
            **hashes,
        }

        return ref

    except Exception as error:
        print(f"  ❌ Capture failed: {error}")
        return {
            'brand_id': brand_id,
            'brand_name': brand_name,
            'official_domains': official_domains,
            'source_url': url,
            'reference_type': reference_type,
            'capture_quality': 'failed',
            'capture_error': str(error),
            'captured_at': datetime.now(timezone.utc).isoformat(),
        }


async def build_all_references():
    """Build references for all brands in brands.yaml."""
    # Load brands
    brands_path = Path(__file__).parent.parent / 'app' / 'core' / 'brands.yaml'
    with open(brands_path) as f:
        brands_data = yaml.safe_load(f)

    brands = brands_data.get('brands', [])
    print(f"Found {len(brands)} brands in brands.yaml")

    # Capture all references
    references = []
    for brand in brands:
        brand_id = brand.get('id')
        brand_name = brand.get('display_name')
        official_domains = brand.get('official_domains', [])
        login_urls = brand.get('login_urls', [])

        if not login_urls:
            print(f"⊘ Skipping {brand_name}: no login_urls defined")
            continue

        # Capture each login URL
        for i, url in enumerate(login_urls):
            ref_type = f'login_{i+1}' if len(login_urls) > 1 else 'login'
            ref = await capture_brand_reference(
                brand_id,
                brand_name,
                url,
                official_domains,
                reference_type=ref_type,
            )
            references.append(ref)

        # Small delay between brands to be polite
        await asyncio.sleep(2)

    return references


def store_references(references: list[dict]):
    """Store references in database and export to JSON."""
    print(f"\nStoring {len(references)} references...")

    # Store in database
    with next(get_sync_session()) as session:
        # Clear existing references
        session.query(BrandReference).delete()

        # Insert new references
        for ref in references:
            # Only store if we have at least one hash
            if ref.get('capture_quality') != 'failed' and ref.get('phash_hex'):
                brand_ref = BrandReference(
                    brand_id=ref['brand_id'],
                    brand_name=ref['brand_name'],
                    official_domains=ref['official_domains'],
                    source_url=ref['source_url'],
                    final_url=ref.get('final_url'),
                    reference_type=ref['reference_type'],
                    capture_quality=ref['capture_quality'],
                    phash_hex=ref.get('phash_hex'),
                    dhash_hex=ref.get('dhash_hex'),
                    upper_phash_hex=ref.get('upper_phash_hex'),
                    favicon_sha256=ref.get('favicon_sha256'),
                    favicon_phash_hex=ref.get('favicon_phash_hex'),
                    captured_at=datetime.fromisoformat(ref['captured_at']),
                )
                session.add(brand_ref)

        session.commit()
        print("✓ Stored in database")

    # Export to JSON
    output_path = Path(__file__).parent.parent / 'data' / 'brand_refs.json'
    output_path.parent.mkdir(exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump({
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'references': references,
        }, f, indent=2)

    print(f"✓ Exported to {output_path}")

    # Print summary
    print("\n=== Summary ===")
    total = len(references)
    good = sum(1 for r in references if r.get('capture_quality') == 'good')
    poor = sum(1 for r in references if r.get('capture_quality') == 'poor')
    failed = sum(1 for r in references if r.get('capture_quality') == 'failed')

    print(f"Total: {total}")
    print(f"Good: {good} ({good/total*100:.1f}%)")
    print(f"Poor: {poor} ({poor/total*100:.1f}%)")
    print(f"Failed: {failed} ({failed/total*100:.1f}%)")

    if failed > 0:
        print("\nFailed captures:")
        for ref in references:
            if ref.get('capture_quality') == 'failed':
                print(f"  - {ref['brand_name']}: {ref.get('capture_error', 'unknown')}")


def main():
    """Main entry point."""
    print("=== Building Brand References ===\n")

    # Run async capture
    references = asyncio.run(build_all_references())

    # Store in DB and export JSON
    store_references(references)

    print("\n✓ Done!")


if __name__ == '__main__':
    main()
