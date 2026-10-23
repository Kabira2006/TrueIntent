"""Pure brand-reference and perceptual-hash matching tests."""

from __future__ import annotations

from pathlib import Path

import imagehash
import pytest
from PIL import Image, ImageDraw

from app.core.sandbox import hamming_distance, match_brand_references
from scripts import seed_brands
from scripts.seed_brands import _load_seed_file, _validate_seed


def _hash_with_bits(bit_count: int) -> str:
    return f"{(1 << bit_count) - 1:016x}"


def test_hamming_distance_counts_different_bits() -> None:
    assert hamming_distance("0000000000000000", "0000000000000001") == 1
    assert hamming_distance("0000000000000000", "000000000000000f") == 4
    assert hamming_distance("0000000000000000", "ffffffffffffffff") == 64


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("", "0000000000000000"),
        ("not-a-hash", "0000000000000000"),
        ("1" * 17, "0000000000000000"),
    ],
)
def test_hamming_distance_rejects_invalid_hashes(left: str, right: str) -> None:
    with pytest.raises(ValueError):
        hamming_distance(left, right)


def test_threshold_produces_high_weak_or_no_indicator() -> None:
    reference = {
        "brand_name": "Example Bank",
        "official_domain": "example.com",
        "phash_signature": "0000000000000000",
    }
    high = match_brand_references(
        _hash_with_bits(10), "login.copycat.test", [reference], threshold=10
    )
    weak = match_brand_references(
        _hash_with_bits(14), "login.copycat.test", [reference], threshold=10
    )
    outside = match_brand_references(
        _hash_with_bits(15), "login.copycat.test", [reference], threshold=10
    )
    assert high[0].code == "VISUAL_BRAND_IMPERSONATION"
    assert high[0].severity == "high"
    assert high[0].evidence == {
        "brand": "Example Bank",
        "distance": 10,
        "threshold": 10,
    }
    assert weak[0].code == "VISUAL_SIMILARITY_WEAK"
    assert weak[0].severity == "low"
    assert outside == []
    assert (
        "the page layout resembles the example bank reference"
        in high[0].message.lower()
    )
    assert "not the brand's official domain" in high[0].message
    assert "fake" not in high[0].message.lower()


@pytest.mark.parametrize("host", ["example.com", "login.example.com"])
def test_official_domain_and_subdomains_are_excluded(host: str) -> None:
    reference = {
        "brand_name": "Example",
        "official_domain": "example.com",
        "phash_signature": "0000000000000000",
    }
    assert (
        match_brand_references("0000000000000000", host, [reference], threshold=10)
        == []
    )


def test_multiple_references_use_closest_match_per_brand() -> None:
    references = [
        {
            "brand_name": "Example",
            "official_domain": "example.com",
            "phash_signature": "0000000000000001",
        },
        {
            "brand_name": "Example",
            "official_domain": "example.com",
            "phash_signature": "000000000000001f",
        },
    ]
    indicators = match_brand_references(
        "0000000000000000",
        "copycat.test",
        references,
        threshold=10,
    )
    assert len(indicators) == 1
    assert indicators[0].evidence["distance"] == 1


def test_invalid_reference_hash_is_ignored() -> None:
    indicator = match_brand_references(
        "0000000000000000",
        "copycat.test",
        [
            {
                "brand_name": "Example",
                "official_domain": "example.com",
                "phash_signature": "invalid",
            }
        ],
        threshold=10,
    )
    assert indicator == []


@pytest.fixture
def local_phash_images(tmp_path: Path) -> tuple[str, str, str]:
    base = Image.new("RGB", (128, 128), "white")
    ImageDraw.Draw(base).rectangle((24, 24, 104, 104), fill="black")
    near = base.copy()
    ImageDraw.Draw(near).rectangle((25, 24, 105, 104), outline="gray", width=1)
    far = Image.new("RGB", (128, 128), "white")
    drawing = ImageDraw.Draw(far)
    for y in range(0, 128, 16):
        for x in range(0, 128, 16):
            if (x // 16 + y // 16) % 2 == 0:
                drawing.rectangle((x, y, x + 15, y + 15), fill="black")
    near_path = tmp_path / "near.png"
    far_path = tmp_path / "far.png"
    near.save(near_path)
    far.save(far_path)
    with Image.open(near_path) as image:
        near_hash = str(imagehash.phash(image))
    with Image.open(far_path) as image:
        far_hash = str(imagehash.phash(image))
    return str(imagehash.phash(base)), near_hash, far_hash


def test_generated_images_have_near_and_far_phash_distances(
    local_phash_images: tuple[str, str, str],
) -> None:
    base_hash, near_hash, far_hash = local_phash_images
    near_distance = hamming_distance(near_hash, base_hash)
    far_distance = hamming_distance(far_hash, base_hash)
    assert near_distance <= 10
    assert far_distance > 14


def test_seed_data_has_all_configured_brand_domains() -> None:
    seed = _load_seed_file()
    _validate_seed(seed)
    assert {brand.official_domains[0] for brand in seed.brands} == {
        "onlinesbi.sbi",
        "hdfcbank.com",
        "icicibank.com",
        "axisbank.com",
        "phonepe.com",
        "paytm.com",
        "flipkart.com",
        "amazon.in",
        "irctc.co.in",
        "uidai.gov.in",
        "indiapost.gov.in",
        "incometax.gov.in",
    }


class _Transaction:
    def __enter__(self) -> object:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None


class _SeedSession:
    def __init__(self) -> None:
        self.added: list[object] = []
        self.executed: list[object] = []

    def begin(self) -> _Transaction:
        return _Transaction()

    def scalar(self, statement: object) -> None:
        return None

    def add(self, value: object) -> None:
        self.added.append(value)

    def execute(self, statement: object) -> None:
        self.executed.append(statement)


def _one_successful_seed_outcome():
    brand = _load_seed_file().brands[0]
    reference = brand.references[0]
    host = str(reference.url.host)
    return [(brand, reference, brand.name, host, "0000000000000000", "LOADED")]


@pytest.mark.parametrize(("refresh", "expected_deletes"), [(False, 0), (True, 1)])
def test_seeder_upserts_and_refreshes_without_network(
    monkeypatch: pytest.MonkeyPatch,
    refresh: bool,
    expected_deletes: int,
) -> None:
    session = _SeedSession()

    def session_generator():
        yield session

    monkeypatch.setattr(seed_brands, "get_sync_session", session_generator)
    states = seed_brands._persist(
        _one_successful_seed_outcome(),
        refresh=refresh,
    )
    assert states[("SBI", "onlinesbi.sbi")] == "SEEDED"
    assert len(session.added) == 1
    assert len(session.executed) == expected_deletes
    assert session.added[0].phash_signature == "0000000000000000"
