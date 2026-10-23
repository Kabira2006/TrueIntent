"""Safely fingerprint official brand pages and store their perceptual hashes."""

import argparse
import asyncio
import logging
import sys
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path
from urllib.parse import urlsplit

import tldextract
import yaml
from pydantic import BaseModel, ConfigDict, HttpUrl, ValidationError
from sqlalchemy import delete, select

from app.core.sandbox import scan_page
from app.db.models import BrandReference
from app.db.session import get_sync_session

_BACKEND = Path(__file__).resolve().parents[1]
_SEED_FILE = _BACKEND / "data" / "brand_seed.yaml"
_SUFFIX_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())
logger = logging.getLogger("seed_brands")


class ReferenceSeed(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str
    url: HttpUrl


class BrandSeed(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    official_domains: list[str]
    references: list[ReferenceSeed]


class SeedFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    brands: list[BrandSeed]


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Replace a brand's stored references when all its configured pages load.",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Check configured pages and print results without connecting to PostgreSQL.",
    )
    return parser.parse_args(argv)


def _load_seed_file(path: Path = _SEED_FILE) -> SeedFile:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        return SeedFile.model_validate(raw)
    except (OSError, yaml.YAMLError, ValidationError) as error:
        raise RuntimeError(
            f"Could not load valid brand seed data from {path.name}."
        ) from error


def _validate_seed(seed: SeedFile) -> None:
    names: set[str] = set()
    for brand in seed.brands:
        if brand.name in names:
            raise ValueError(f"Duplicate brand name: {brand.name}")
        names.add(brand.name)
        if not brand.official_domains or not brand.references:
            raise ValueError(f"{brand.name} needs a domain and at least one reference.")
        for domain in brand.official_domains:
            if _registered_domain(domain) != domain.lower().rstrip("."):
                raise ValueError(
                    f"{brand.name} official domain must be a registrable domain."
                )
        for reference in brand.references:
            parsed = urlsplit(str(reference.url))
            if parsed.scheme != "https":
                raise ValueError(f"{brand.name} reference URL must use HTTPS.")
            if not _host_is_official(parsed.hostname or "", brand.official_domains):
                raise ValueError(
                    f"{brand.name} reference URL is outside its official domains."
                )


def _registered_domain(value: str) -> str:
    extracted = _SUFFIX_EXTRACTOR(value.lower().rstrip("."))
    return extracted.top_domain_under_public_suffix or value.lower().rstrip(".")


def _host_is_official(host: str, official_domains: list[str]) -> bool:
    host = host.lower().rstrip(".")
    host_domain = _registered_domain(host)
    return any(
        host == domain.lower().rstrip(".")
        or host.endswith(f".{domain.lower().rstrip('.')}")
        or host_domain == domain.lower().rstrip(".")
        for domain in official_domains
    )


async def _check_reference(
    brand: BrandSeed,
    reference: ReferenceSeed,
) -> tuple[str, str, str | None, str]:
    host = urlsplit(str(reference.url)).hostname or ""
    try:
        result = await scan_page(str(reference.url))
    except Exception as error:  # noqa: BLE001 - report every failed official-site check
        logger.warning(
            "brand reference check failed brand=%s host=%s error_type=%s",
            brand.name,
            host,
            type(error).__name__,
        )
        return brand.name, host, None, f"HUMAN_REVIEW ({type(error).__name__})"
    phash = result.features.get("phash")
    final_host = str(result.features.get("final_host") or "")
    if (
        result.status == "UNAVAILABLE"
        or not isinstance(phash, str)
        or not final_host
        or not _host_is_official(final_host, brand.official_domains)
    ):
        note = "page did not load or ended outside configured official domains"
        return brand.name, host, None, f"HUMAN_REVIEW ({note})"
    if not _host_is_official(host, brand.official_domains):
        return brand.name, host, None, "HUMAN_REVIEW (seed URL is not official)"
    return brand.name, host, phash, "LOADED"


async def _check_all(
    seed: SeedFile,
) -> list[tuple[BrandSeed, ReferenceSeed, str, str, str | None, str]]:
    outcomes: list[tuple[BrandSeed, ReferenceSeed, str, str, str | None, str]] = []
    for brand in seed.brands:
        for reference in brand.references:
            name, host, phash, status = await _check_reference(brand, reference)
            outcomes.append((brand, reference, name, host, phash, status))
    return outcomes


def _persist(
    outcomes: list[tuple[BrandSeed, ReferenceSeed, str, str, str | None, str]],
    *,
    refresh: bool,
) -> dict[tuple[str, str], str]:
    completed: dict[tuple[str, str], list[tuple[BrandSeed, str, str]]] = {}
    states: dict[tuple[str, str], str] = {}
    for brand, _reference, _name, host, phash, status in outcomes:
        if phash is None:
            continue
        for official_domain in brand.official_domains:
            key = (brand.name, official_domain)
            completed.setdefault(key, []).append((brand, host, phash))
            states[(brand.name, host)] = status

    session_generator: Iterator = get_sync_session()
    with closing(session_generator) as generator:
        session = next(generator)
        with session.begin():
            for (brand_name, official_domain), rows in completed.items():
                brand = rows[0][0]
                reference_count = sum(
                    1
                    for row_brand, _ref, _name, _host, _hash, _status in outcomes
                    if row_brand.name == brand_name
                )
                successful_count = sum(
                    1
                    for row_brand, _ref, _name, _host, row_hash, _status in outcomes
                    if row_brand.name == brand_name and row_hash is not None
                )
                if refresh and reference_count == successful_count:
                    session.execute(
                        delete(BrandReference).where(
                            BrandReference.brand_name == brand_name,
                            BrandReference.official_domain == official_domain,
                        )
                    )

                for _brand, _host, phash in rows:
                    existing = session.scalar(
                        select(BrandReference).where(
                            BrandReference.brand_name == brand_name,
                            BrandReference.official_domain == official_domain,
                            BrandReference.phash_signature == phash,
                        )
                    )
                    if existing is None:
                        session.add(
                            BrandReference(
                                brand_name=brand.name,
                                official_domain=official_domain,
                                phash_signature=phash,
                            )
                        )
                        states[(brand_name, _host)] = "SEEDED"
                    else:
                        states[(brand_name, _host)] = "ALREADY_STORED"
    return states


def _print_table(
    outcomes: list[tuple[BrandSeed, ReferenceSeed, str, str, str | None, str]],
    persisted: dict[tuple[str, str], str],
) -> None:
    print(f"{'Brand':<23} {'Domain':<28} {'Hash':<16} Status / notes")
    print("-" * 100)
    for brand, _reference, name, host, phash, status in outcomes:
        if phash is None:
            final_status = status
        else:
            final_status = persisted.get((name, host), status)
        print(f"{name:<23} {host:<28} {(phash or '-'): <16} {final_status}")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    seed = _load_seed_file()
    _validate_seed(seed)
    outcomes = asyncio.run(_check_all(seed))
    if args.verify_only:
        _print_table(outcomes, {})
        return 0 if all(row[4] is not None for row in outcomes) else 1

    try:
        states = _persist(outcomes, refresh=args.refresh)
    except Exception as error:
        logger.exception(
            "brand references could not be saved (%s)", type(error).__name__
        )
        _print_table(outcomes, {})
        return 2
    _print_table(outcomes, states)
    return 0 if all(row[4] is not None for row in outcomes) else 1


if __name__ == "__main__":
    sys.exit(main())
