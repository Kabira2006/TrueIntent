"""Build a locally stored, domain-split URL dataset from documented sources."""

import argparse
import csv
import hashlib
import io
import json
import os
import random
import re
import sys
import zipfile
from collections import defaultdict
from collections.abc import Iterable
from datetime import date
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

import httpx
import tldextract
from pydantic import BaseModel, ConfigDict, Field

EVAL_DIR = Path(__file__).resolve().parent
DATA_DIR = EVAL_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
_TRANCO_METADATA_URL = "https://tranco-list.eu/api/lists/date/latest"
_TRANCO_TOP_1M_FALLBACK = "https://tranco-list.eu/top-1m.csv.zip"
_OPENPHISH_FEED = "https://openphish.com/feed.txt"
_URLHAUS_RECENT = "https://urlhaus-api.abuse.ch/v2/urls/recent/"
_PHISHTANK_FEED = "https://data.phishtank.com/data/{key}/online-valid.csv"
_SUFFIX_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())
_SOURCES = (
    (
        "OpenPhish Community Feed",
        "https://openphish.com/terms.html",
        (
            "Research/personal use only under its terms; no commercial use or "
            "redistribution without written permission. This dataset is local-only."
        ),
    ),
    (
        "URLhaus Community API",
        "https://abuse.ch/terms-of-use/",
        (
            "Authentication required; free access is for authenticated non-profit "
            "use within fair-use limits. Terms prohibit using its data to train AI "
            "without prior written consent. This evaluation does not train a model."
        ),
    ),
    (
        "PhishTank",
        "https://phishtank.org/terms.php",
        (
            "Optional API-key feed. The site points to Cisco's current end-user "
            "agreement; review it before use. The archived terms describe its Data "
            "as available for commercial use but disclaim accuracy."
        ),
    ),
    (
        "Tranco",
        "https://tranco-list.eu/",
        (
            "Research-oriented popularity ranking. The API documents reproducible "
            "daily lists; no separate dataset license was stated on the checked "
            "official pages. Keep attribution and the list ID with local results."
        ),
    ),
)


class DatasetRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    row_id: str
    input: str = Field(min_length=1)
    label: Literal["malicious", "benign"]
    source: str
    registered_domain: str
    synthetic: bool = False


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20261024)
    parser.add_argument("--benign-count", type=int, default=500)
    parser.add_argument("--malicious-per-source", type=int, default=1000)
    parser.add_argument(
        "--accept-openphish-research-terms",
        action="store_true",
        help="Confirm the non-commercial research and no-redistribution terms.",
    )
    return parser.parse_args(argv)


def _canonical_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("dataset entries must be absolute HTTP(S) URLs")
    host = parsed.hostname.lower().rstrip(".")
    if ":" in host:
        host = f"[{host}]"
    netloc = host
    if parsed.port is not None:
        netloc = f"{host}:{parsed.port}"
    return urlunsplit(
        (parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, "")
    )


def _registered_domain(value: str) -> str:
    host = urlsplit(value).hostname
    if not host:
        return ""
    extracted = _SUFFIX_EXTRACTOR(host)
    return extracted.top_domain_under_public_suffix or host.lower()


def split_by_registered_domain(
    rows: list[DatasetRow],
    *,
    seed: int,
    ratios: tuple[float, float, float] = (0.8, 0.1, 0.1),
) -> dict[str, list[DatasetRow]]:
    """Assign every row for a registrable domain to one deterministic split."""
    if len(ratios) != 3 or any(ratio <= 0 for ratio in ratios):
        raise ValueError("three positive split ratios are required")
    if abs(sum(ratios) - 1.0) > 1e-9:
        raise ValueError("split ratios must sum to one")

    groups: dict[str, list[DatasetRow]] = defaultdict(list)
    for row in rows:
        if not row.registered_domain:
            raise ValueError(f"row {row.row_id} has no registered domain")
        groups[row.registered_domain].append(row)

    names = ("train", "dev", "test")
    shuffled_domains = list(groups)
    random.Random(seed).shuffle(shuffled_domains)
    targets = [len(rows) * ratio for ratio in ratios]
    counts = [0, 0, 0]
    assigned: dict[str, list[DatasetRow]] = {name: [] for name in names}
    for domain in shuffled_domains:
        domain_rows = groups[domain]
        best_index = min(
            range(3),
            key=lambda index: (
                (
                    (counts[index] + len(domain_rows) - targets[index]) ** 2
                    - (counts[index] - targets[index]) ** 2
                )
                / max(targets[index], 1)
            ),
        )
        assigned[names[best_index]].extend(domain_rows)
        counts[best_index] += len(domain_rows)
    return assigned


def _deduplicate(rows: list[DatasetRow]) -> list[DatasetRow]:
    by_url: dict[str, DatasetRow] = {}
    conflicts: set[str] = set()
    for row in rows:
        canonical = _canonical_url(row.input)
        previous = by_url.get(canonical)
        if previous and previous.label != row.label:
            conflicts.add(canonical)
            continue
        if previous is None:
            digest = hashlib.sha256(canonical.encode()).hexdigest()[:16]
            by_url[canonical] = row.model_copy(
                update={
                    "row_id": digest,
                    "input": canonical,
                    "registered_domain": _registered_domain(canonical),
                }
            )
        elif row.source not in previous.source.split(";"):
            by_url[canonical] = previous.model_copy(
                update={"source": f"{previous.source};{row.source}"}
            )
    for canonical in conflicts:
        by_url.pop(canonical, None)
    return list(by_url.values())


def _write_split(
    path: Path,
    split: list[DatasetRow],
    *,
    name: str,
    seed: int,
    tranco_list_id: str,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as output:
        output.write(
            f"# {name} split; fixed seed={seed}; generated {date.today().isoformat()}\n"
        )
        output.write(
            "# Keep this dataset local. Never tune thresholds or model choices on "
            "test_locked.csv.\n"
        )
        output.write(f"# Tranco list ID: {tranco_list_id}\n")
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "row_id",
                "input",
                "label",
                "source",
                "registered_domain",
                "synthetic",
            ],
        )
        writer.writeheader()
        writer.writerows(row.model_dump() for row in split)


def _download(
    client: httpx.Client,
    url: str,
    *,
    name: str,
    headers: dict[str, str] | None = None,
    data: dict[str, str] | None = None,
) -> bytes:
    try:
        response = (
            client.post(url, headers=headers, data=data)
            if data is not None
            else client.get(url, headers=headers)
        )
        response.raise_for_status()
        payload = response.content
    except httpx.HTTPError as error:
        raise RuntimeError(
            f"Could not retrieve {name} ({type(error).__name__})."
        ) from None
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    (RAW_DIR / name).write_bytes(payload)
    return payload


def _openphish_rows(
    client: httpx.Client, *, accepted: bool, limit: int
) -> list[DatasetRow]:
    if not accepted:
        print(
            "OpenPhish skipped: pass --accept-openphish-research-terms only for "
            "permitted non-commercial research; its terms prohibit redistribution."
        )
        return []
    payload = _download(
        client,
        _OPENPHISH_FEED,
        name=f"openphish-{date.today().isoformat()}.txt",
    )
    urls = [line.strip() for line in payload.decode("utf-8", "replace").splitlines()]
    return _malicious_rows(urls, "OpenPhish", limit)


def _urlhaus_rows(
    client: httpx.Client, *, auth_key: str | None, limit: int
) -> list[DatasetRow]:
    if not auth_key:
        print("URLhaus skipped: URLHAUS_AUTH_KEY is not configured.")
        return []
    payload = _download(
        client,
        _URLHAUS_RECENT,
        name=f"urlhaus-recent-{date.today().isoformat()}.json",
        headers={"Auth-Key": auth_key},
        data={"limit": str(min(limit, 1000))},
    )
    try:
        urls = [
            str(item["url"])
            for item in json.loads(payload).get("urls", [])
            if isinstance(item, dict) and item.get("url")
        ]
    except (json.JSONDecodeError, AttributeError, TypeError) as error:
        raise RuntimeError("URLhaus returned an unexpected response.") from error
    return _malicious_rows(urls, "URLhaus", limit)


def _phishtank_rows(
    client: httpx.Client, *, api_key: str | None, limit: int
) -> list[DatasetRow]:
    if not api_key:
        print("PhishTank skipped: PHISHTANK_API_KEY is not configured.")
        return []
    payload = _download(
        client,
        _PHISHTANK_FEED.format(key=api_key),
        name=f"phishtank-{date.today().isoformat()}.csv",
    )
    rows = csv.DictReader(io.StringIO(payload.decode("utf-8", "replace")))
    urls = [
        row["url"]
        for row in rows
        if row.get("url") and row.get("verified", "").lower() in {"yes", "y"}
    ]
    return _malicious_rows(urls, "PhishTank", limit)


def _malicious_rows(urls: list[str], source: str, limit: int) -> list[DatasetRow]:
    rows: list[DatasetRow] = []
    seen: set[str] = set()
    for value in urls:
        try:
            url = _canonical_url(value)
        except ValueError:
            continue
        if url in seen:
            continue
        domain = _registered_domain(url)
        if not domain:
            continue
        seen.add(url)
        digest = hashlib.sha256(url.encode()).hexdigest()[:16]
        rows.append(
            DatasetRow(
                row_id=digest,
                input=url,
                label="malicious",
                source=source,
                registered_domain=domain,
            )
        )
        if len(rows) >= limit:
            break
    return rows


def _tranco_rows(
    client: httpx.Client, *, count: int, seed: int
) -> tuple[list[DatasetRow], str]:
    try:
        metadata_response = client.get(_TRANCO_METADATA_URL)
        metadata_response.raise_for_status()
        metadata = metadata_response.json()
    except (httpx.HTTPError, ValueError) as error:
        raise RuntimeError(
            f"Could not get Tranco list metadata ({type(error).__name__})."
        ) from None
    list_id = str(metadata.get("list_id") or "latest")
    download_url = str(metadata.get("download") or _TRANCO_TOP_1M_FALLBACK)
    safe_list_id = re.sub(r"[^A-Za-z0-9_-]", "_", list_id)
    local_copy = RAW_DIR / f"tranco-{safe_list_id}.csv"
    if not local_copy.exists():
        legacy_copy = RAW_DIR / f"tranco-{safe_list_id}.zip"
        if legacy_copy.exists():
            local_copy = legacy_copy
    archive = (
        local_copy.read_bytes()
        if local_copy.exists()
        else _download(
            client,
            download_url,
            name=f"tranco-{safe_list_id}.csv",
        )
    )
    try:
        candidates = _parse_tranco_candidates(archive)
    except (zipfile.BadZipFile, StopIteration, OSError, ValueError) as error:
        raise RuntimeError(
            f"Could not parse the Tranco list ({type(error).__name__})."
        ) from None
    if not candidates:
        raise RuntimeError("Tranco returned no domains in ranks 1,001 through 100,000.")
    sample = random.Random(seed).sample(candidates, min(count, len(candidates)))
    rows = []
    for _rank, domain in sample:
        url = f"https://{domain.lower()}/"
        digest = hashlib.sha256(url.encode()).hexdigest()[:16]
        rows.append(
            DatasetRow(
                row_id=digest,
                input=url,
                label="benign",
                source="Tranco",
                registered_domain=_registered_domain(url),
            )
        )
    return rows, list_id


def _parse_tranco_candidates(payload: bytes) -> list[tuple[int, str]]:
    archive = io.BytesIO(payload)
    if zipfile.is_zipfile(archive):
        archive.seek(0)
        with zipfile.ZipFile(archive) as bundle:
            member = next(
                name for name in bundle.namelist() if name.lower().endswith(".csv")
            )
            with bundle.open(member) as stream:
                text = io.TextIOWrapper(stream, encoding="utf-8")
                return _ranked_domains(csv.reader(text))
    source = io.StringIO(payload.decode("utf-8-sig"))
    return _ranked_domains(csv.reader(source))


def _ranked_domains(entries: Iterable[list[str]]) -> list[tuple[int, str]]:
    candidates: list[tuple[int, str]] = []
    for entry in entries:
        if len(entry) < 2:
            continue
        rank, domain = entry[0].strip(), entry[1].strip()
        if rank.isdigit() and 1000 < int(rank) <= 100_000 and domain:
            candidates.append((int(rank), domain))
    return candidates


def build_dataset(
    *,
    seed: int = 20261024,
    benign_count: int = 500,
    malicious_per_source: int = 1000,
    accept_openphish_terms: bool = False,
    client: httpx.Client | None = None,
) -> dict[str, int]:
    """Fetch permitted public sources, deduplicate, and write fixed domain splits."""
    if benign_count < 1 or malicious_per_source < 1:
        raise ValueError("sample limits must be positive")
    print("Source access and license notes:")
    for source, terms_url, note in _SOURCES:
        print(f"- {source} ({terms_url}): {note}")

    owned_client = client is None
    http_client = client or httpx.Client(
        timeout=httpx.Timeout(30.0, connect=10.0),
        follow_redirects=True,
        headers={"User-Agent": "TrueIntent-evaluation/1.0 (research dataset builder)"},
    )
    try:
        malicious = [
            *_openphish_rows(
                http_client,
                accepted=accept_openphish_terms,
                limit=malicious_per_source,
            ),
            *_urlhaus_rows(
                http_client,
                auth_key=os.getenv("URLHAUS_AUTH_KEY"),
                limit=malicious_per_source,
            ),
            *_phishtank_rows(
                http_client,
                api_key=os.getenv("PHISHTANK_API_KEY"),
                limit=malicious_per_source,
            ),
        ]
        benign, list_id = _tranco_rows(http_client, count=benign_count, seed=seed)
    finally:
        if owned_client:
            http_client.close()

    rows = _deduplicate([*malicious, *benign])
    if not any(row.label == "malicious" for row in rows):
        raise RuntimeError(
            "No malicious examples were obtained. Configure an eligible source "
            "and retry; no empty or synthetic locked split was written."
        )
    splits = split_by_registered_domain(rows, seed=seed)
    _write_split(
        DATA_DIR / "train.csv",
        splits["train"],
        name="train",
        seed=seed,
        tranco_list_id=list_id,
    )
    _write_split(
        DATA_DIR / "dev.csv",
        splits["dev"],
        name="dev",
        seed=seed,
        tranco_list_id=list_id,
    )
    _write_split(
        DATA_DIR / "test_locked.csv",
        splits["test"],
        name="LOCKED TEST - DO NOT USE FOR TUNING",
        seed=seed,
        tranco_list_id=list_id,
    )
    counts = {name: len(split) for name, split in splits.items()}
    print(
        f"Tranco list {list_id}; {len(malicious)} malicious and {len(benign)} "
        f"benign rows before deduplication; split counts {counts}."
    )
    print("The locked test split is local-only and must not be used for tuning.")
    return counts


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        build_dataset(
            seed=args.seed,
            benign_count=args.benign_count,
            malicious_per_source=args.malicious_per_source,
            accept_openphish_terms=args.accept_openphish_research_terms,
        )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Dataset build stopped: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
