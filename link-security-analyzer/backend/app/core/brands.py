"""Brand reference data and typosquat detection.

Loads ``app/core/brands.yaml`` (25-30 starter brands from spec Appendix A) and
exposes:

* ``load_brands()`` - the brand catalogue
* ``is_official(domain, brand)`` - whether a domain is an official brand domain
  or a legitimate subdomain of one (never flagged)
* ``typosquat_match(label, brands)`` - whether a label look-alikes a brand, using
  Levenshtein distance plus a confusable character map
* ``brand_in_subdomain_or_path(subdomains, path, brands)`` - brand keyword
  appearing in a subdomain or path while the registrable domain is not official

All logic is offline and pure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from app.core._util import _levenshtein, _normalize_for_compare

_BRANDS_PATH = Path(__file__).resolve().parent / "brands.yaml"

#: Maximum Levenshtein distance for a typosquat match on normal-length labels.
TYPO_MAX_DISTANCE = 2
#: Shorter labels need a tighter distance to avoid false positives.
TYPO_MAX_DISTANCE_SHORT = 1
_SHORT_LABEL_LEN = 6


@dataclass(frozen=True)
class Brand:
    """One reference brand."""

    id: str
    display_name: str
    keywords: tuple[str, ...] = ()
    official_domains: tuple[str, ...] = ()
    login_urls: tuple[str, ...] = ()
    notes: str = ""


@dataclass(frozen=True)
class TyposquatMatch:
    """Result of comparing one label against one brand."""

    brand_id: str
    brand_display: str
    distance: int
    matched_label: str
    normalized_label: str
    normalized_brand: str


@dataclass(frozen=True)
class BrandCatalog:
    """Loaded brand catalogue with lookup helpers."""

    brands: tuple[Brand, ...] = ()
    _by_id: dict[str, Brand] = field(default_factory=dict, repr=False)
    _official_domains: dict[str, str] = field(default_factory=dict, repr=False)
    _brand_labels: dict[str, tuple[str, ...]] = field(default_factory=dict, repr=False)

    def brand(self, brand_id: str) -> Brand | None:
        return self._by_id.get(brand_id)

    def official_domain_for(self, domain: str) -> str | None:
        """Return the brand id that owns ``domain`` as an official domain."""
        return self._official_domains.get(domain.lower())

    def labels_for(self, brand_id: str) -> tuple[str, ...]:
        return self._brand_labels.get(brand_id, ())


def load_brands(path: Path = _BRANDS_PATH) -> BrandCatalog:
    """Load the brand catalogue from ``brands.yaml``."""
    with path.open(encoding="utf-8") as brand_file:
        raw = yaml.safe_load(brand_file) or {}
    entries = raw.get("brands", []) if isinstance(raw, dict) else []
    brands: list[Brand] = []
    official_domains: dict[str, str] = {}
    brand_labels: dict[str, tuple[str, ...]] = {}
    for entry in entries:
        brand = Brand(
            id=str(entry.get("id", "")),
            display_name=str(entry.get("display_name", "")),
            keywords=tuple(str(k).lower() for k in entry.get("keywords", []) or []),
            official_domains=tuple(
                str(d).lower() for d in entry.get("official_domains", []) or []
            ),
            login_urls=tuple(str(u) for u in entry.get("login_urls", []) or []),
            notes=str(entry.get("notes", "")),
        )
        brands.append(brand)
        for domain in brand.official_domains:
            official_domains[domain] = brand.id
        labels = {brand.id, brand.display_name.lower()}
        labels.update(brand.keywords)
        brand_labels[brand.id] = tuple(sorted(labels))
    return BrandCatalog(
        brands=tuple(brands),
        _by_id={brand.id: brand for brand in brands},
        _official_domains=official_domains,
        _brand_labels=brand_labels,
    )


def _domain_labels(domain: str) -> tuple[str, ...]:
    return tuple(domain.lower().rstrip(".").split("."))


def is_official(domain: str | None, catalog: BrandCatalog) -> bool:
    """True if ``domain`` is an official brand domain or subdomain of one.

    Official domains and their subdomains are never flagged as typosquats or
    brand mismatches (e.g. netbanking.hdfcbank.com, www.sbi.co.in).
    """
    if not domain:
        return False
    domain = domain.lower().rstrip(".")
    labels = _domain_labels(domain)
    # Walk from the registrable domain upward: any suffix that is an official
    # domain means this host belongs to the brand.
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in catalog._official_domains:
            return True
    return False


def typosquat_match(label: str, catalog: BrandCatalog) -> TyposquatMatch | None:
    """Compare one host label against every brand label/keyword.

    Returns the closest match when the normalised Levenshtein distance is within
    threshold (<=2, or <=1 for labels <=6 chars).  Official domains are excluded
    by the caller.
    """
    if not label:
        return None
    label_l = label.lower()
    label_norm = _normalize_for_compare(label_l)
    max_distance = (
        TYPO_MAX_DISTANCE_SHORT
        if len(label_norm) <= _SHORT_LABEL_LEN
        else TYPO_MAX_DISTANCE
    )

    best: TyposquatMatch | None = None
    for brand in catalog.brands:
        for brand_label in catalog.labels_for(brand.id):
            brand_norm = _normalize_for_compare(brand_label.lower())
            distance = _levenshtein(label_norm, brand_norm)
            if distance <= max_distance:
                match = TyposquatMatch(
                    brand_id=brand.id,
                    brand_display=brand.display_name,
                    distance=distance,
                    matched_label=label_l,
                    normalized_label=label_norm,
                    normalized_brand=brand_norm,
                )
                if best is None or distance < best.distance:
                    best = match
    return best


def brand_in_subdomain_or_path(
    subdomains: tuple[str, ...],
    path: str,
    catalog: BrandCatalog,
    registrable_domain: str | None,
) -> str | None:
    """Return a brand id if a brand keyword appears in a subdomain or path while
    the registrable domain is not that brand's official domain."""
    path_l = (path or "").lower()
    for sub in subdomains:
        sub_l = sub.lower()
        for brand in catalog.brands:
            if is_official(registrable_domain, catalog):
                continue
            for keyword in brand.keywords:
                if keyword and (keyword in sub_l or keyword in path_l):
                    return brand.id
    return None
