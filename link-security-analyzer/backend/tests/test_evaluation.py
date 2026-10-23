"""Evaluation helper tests; every fixture is synthetic and network-free."""

import csv
import importlib
import sys
from pathlib import Path

import pytest

EVAL_DIR = Path(__file__).resolve().parents[2] / "eval"
BACKEND_DIR = EVAL_DIR.parent / "backend"
if str(EVAL_DIR.parent) not in sys.path:
    sys.path.insert(0, str(EVAL_DIR.parent))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from eval.build_dataset import (
    DatasetRow,
    _canonical_url,
    _deduplicate,
    _parse_tranco_candidates,
    _registered_domain,
    split_by_registered_domain,
)
from eval.run_eval import (
    EvalResult,
    EvalRow,
    _indicator_rates,
    _input_hash,
    _offline_result,
    _pending_rows,
    _rate_metrics,
    read_dataset,
    summarize,
)


def _row(
    row_id: str,
    domain: str,
    *,
    label: str = "malicious",
    url: str | None = None,
) -> DatasetRow:
    value = url or f"https://{domain}/path/{row_id}"
    return DatasetRow(
        row_id=row_id,
        input=value,
        label=label,
        source="synthetic",
        registered_domain=domain,
    )


def test_canonical_url_normalizes_host_scheme_and_fragment() -> None:
    assert (
        _canonical_url("HTTPS://Sub.Example.com:443/a#fragment")
        == "https://sub.example.com:443/a"
    )


def test_registered_domain_removes_subdomain_and_honors_multilevel_suffix() -> None:
    assert (
        _registered_domain("https://login.shop.example.co.uk/path") == "example.co.uk"
    )


def test_deduplication_merges_sources_and_drops_conflicting_labels() -> None:
    shared = "https://www.example.com/path"
    rows = [
        _row("one", "example.com", url=shared),
        _row("two", "example.com", url="HTTPS://WWW.EXAMPLE.COM/path#discard"),
        _row("three", "example.net", label="benign", url="https://example.net/"),
        _row(
            "four", "example.net", label="benign", url="https://example.net/"
        ).model_copy(update={"source": "Tranco"}),
        _row(
            "conflict",
            "example.com",
            label="benign",
            url="https://www.example.com/path",
        ),
    ]
    deduplicated = _deduplicate(rows)
    assert len(deduplicated) == 1
    assert deduplicated[0].registered_domain == "example.net"
    assert deduplicated[0].source == "synthetic;Tranco"


def test_domain_splits_are_deterministic_and_do_not_leak() -> None:
    rows = [
        _row("a1", "example.com"),
        _row("a2", "example.com", url="https://sub.example.com/two"),
        _row("b1", "example.net", label="benign"),
        _row("c1", "example.org"),
        _row("d1", "example.io", label="benign"),
        _row("e1", "example.dev"),
        _row("f1", "example.co.uk", label="benign"),
        _row("g1", "example.test"),
        _row("h1", "example.edu", label="benign"),
        _row("i1", "example.xyz"),
    ]
    first = split_by_registered_domain(rows, seed=19)
    second = split_by_registered_domain(rows, seed=19)
    assert first == second
    split_domains = {
        name: {row.registered_domain for row in split} for name, split in first.items()
    }
    assert split_domains["train"].isdisjoint(split_domains["dev"])
    assert split_domains["train"].isdisjoint(split_domains["test"])
    assert split_domains["dev"].isdisjoint(split_domains["test"])
    assert sum(map(len, first.values())) == len(rows)


def test_domain_split_rejects_invalid_ratios() -> None:
    with pytest.raises(ValueError, match="sum to one"):
        split_by_registered_domain([], seed=1, ratios=(0.7, 0.2, 0.2))


def test_tranco_parser_samples_only_ranks_1001_through_100000() -> None:
    payload = (
        b"1,top.example\n"
        b"1000,edge.example\n"
        b"1001,included.example\n"
        b"100000,included2.example\n"
        b"100001,outside.example\n"
    )
    assert _parse_tranco_candidates(payload) == [
        (1001, "included.example"),
        (100000, "included2.example"),
    ]


def test_dataset_builder_uses_mocked_feeds_and_writes_domain_splits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = importlib.import_module("eval.build_dataset")

    class _Response:
        def __init__(
            self, content: bytes = b"", payload: dict[str, str] | None = None
        ) -> None:
            self.content = content
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            assert self._payload is not None
            return self._payload

    class _Client:
        def get(self, url: str, **kwargs: object) -> _Response:
            if url == builder._OPENPHISH_FEED:
                return _Response(
                    b"https://sample-bad-one.test/a\nhttps://sample-bad-two.test/b\n"
                )
            if url == builder._TRANCO_METADATA_URL:
                return _Response(
                    payload={
                        "list_id": "sample123",
                        "download": "https://tranco.example/list.csv",
                    }
                )
            if url == "https://tranco.example/list.csv":
                csv_data = "".join(
                    f"{rank},benign-{rank}.example\n" for rank in range(1001, 1021)
                )
                return _Response(csv_data.encode())
            raise AssertionError("unexpected dataset URL")

        def post(self, url: str, **kwargs: object) -> _Response:
            raise AssertionError("optional keyed feeds should be skipped")

    monkeypatch.setattr(builder, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(builder, "RAW_DIR", tmp_path / "raw")
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    monkeypatch.delenv("PHISHTANK_API_KEY", raising=False)
    counts = builder.build_dataset(
        seed=44,
        benign_count=8,
        malicious_per_source=2,
        accept_openphish_terms=True,
        client=_Client(),
    )
    assert sum(counts.values()) >= 10
    locked = tmp_path / "data" / "test_locked.csv"
    assert "Never tune" in locked.read_text(encoding="utf-8")
    split_rows = {
        name: read_dataset(tmp_path / "data" / f"{name}.csv")
        for name in ("train", "dev", "test_locked")
    }
    domains = {
        name: {row.input.split("/")[2] for row in rows}
        for name, rows in split_rows.items()
    }
    assert domains["train"].isdisjoint(domains["dev"])
    assert domains["train"].isdisjoint(domains["test_locked"])
    assert domains["dev"].isdisjoint(domains["test_locked"])
    assert all(not row.synthetic for rows in split_rows.values() for row in rows)


def test_metric_calculation_counts_false_alarms_and_misses() -> None:
    results = [
        EvalResult(
            row_id="p1",
            input="",
            input_hash="1",
            label="malicious",
            source="test",
            synthetic=True,
            score=0.8,
            indicator_codes=["A"],
            status="FLAGGED",
            unavailable_checks=[],
        ),
        EvalResult(
            row_id="p2",
            input="",
            input_hash="2",
            label="malicious",
            source="test",
            synthetic=True,
            score=0.1,
            indicator_codes=[],
            status="NO_INDICATORS_DETECTED",
            unavailable_checks=[],
        ),
        EvalResult(
            row_id="b1",
            input="",
            input_hash="3",
            label="benign",
            source="test",
            synthetic=True,
            score=0.9,
            indicator_codes=["A"],
            status="FLAGGED",
            unavailable_checks=[],
        ),
        EvalResult(
            row_id="b2",
            input="",
            input_hash="4",
            label="benign",
            source="test",
            synthetic=True,
            score=0.2,
            indicator_codes=[],
            status="NO_INDICATORS_DETECTED",
            unavailable_checks=[],
        ),
    ]
    metrics = _rate_metrics(results, 0.5)
    assert metrics == {
        "threshold": 0.5,
        "precision": 0.5,
        "recall": 0.5,
        "f1": 0.5,
        "false_positive_rate": 0.5,
        "true_positive": 1,
        "false_positive": 1,
        "false_negative": 1,
        "true_negative": 1,
    }


def test_offline_upi_analysis_uses_real_parser_without_network() -> None:
    result = _offline_result(
        EvalRow(
            row_id="upi-collect",
            input="upi://collect?pa=demo%40newpsp&tn=Urgent%20refund",
            label="malicious",
            source="synthetic",
            synthetic=True,
        )
    )
    assert "UPI_COLLECT_REQUEST" in result.indicator_codes
    assert "SUSPICIOUS_NOTE_TEXT" in result.indicator_codes
    assert result.score > 0
    assert result.synthetic


def test_comment_header_dataset_reading(tmp_path: Path) -> None:
    path = tmp_path / "dataset.csv"
    path.write_text(
        "# keep locked test split out of tuning\n"
        "row_id,input,label,source,synthetic\n"
        "r1,https://example.com/,benign,tranco,false\n",
        encoding="utf-8",
    )
    assert read_dataset(path)[0].row_id == "r1"


def test_india_manual_set_has_at_least_30_explicitly_synthetic_rows() -> None:
    rows = read_dataset(EVAL_DIR / "data" / "india_manual.csv")
    assert len(rows) >= 30
    assert all(row.synthetic for row in rows)
    assert {row.label for row in rows} == {"malicious", "benign"}


def test_resume_skips_only_rows_with_matching_identity_and_label() -> None:
    completed = EvalResult(
        row_id="r1",
        input="https://example.com/",
        input_hash="digest",
        label="benign",
        source="tranco",
        synthetic=False,
        score=0.0,
        indicator_codes=[],
        status="INCONCLUSIVE",
        unavailable_checks=[],
    )
    same_row = EvalRow(
        row_id="r1",
        input="https://example.com/",
        label="benign",
        source="tranco",
        synthetic=False,
    )
    changed_label = same_row.model_copy(update={"label": "malicious"})
    progress = {_input_hash(same_row.input): completed}
    assert _pending_rows([same_row], progress) == []
    assert _pending_rows([changed_label], progress) == [changed_label]


def test_summary_writes_manual_review_files_and_png(tmp_path: Path) -> None:
    results = [
        EvalResult(
            row_id="r1",
            input="upi://pay?pa=x%40oksbi",
            input_hash="digest1",
            label="malicious",
            source="synthetic",
            synthetic=True,
            score=0.3,
            indicator_codes=["UPI_COLLECT_REQUEST"],
            status="FLAGGED",
            unavailable_checks=[],
        ),
        EvalResult(
            row_id="r2",
            input="https://example.test/",
            input_hash="digest2",
            label="benign",
            source="synthetic",
            synthetic=True,
            score=0.0,
            indicator_codes=[],
            status="INCONCLUSIVE",
            unavailable_checks=["URL lexical analysis"],
        ),
    ]
    summary = summarize(results, output_dir=tmp_path, dataset_name="sample")
    assert summary["row_count"] == 2
    assert (tmp_path / "sample_indicator_rates.csv").exists()
    assert (tmp_path / "sample_threshold_metrics.csv").exists()
    assert (tmp_path / "sample_worst_false_negatives.csv").exists()
    assert (tmp_path / "sample_precision_recall.png").stat().st_size > 100
    with (tmp_path / "sample_indicator_rates.csv").open(
        encoding="utf-8", newline=""
    ) as source:
        codes = {row["indicator_code"] for row in csv.DictReader(source)}
        assert "UPI_COLLECT_REQUEST" in codes
        assert "DOMAIN_VERY_NEW" in codes


def test_indicator_rates_exclude_check_availability_codes() -> None:
    results = [
        EvalResult(
            row_id="r1",
            input="",
            input_hash="1",
            label="malicious",
            source="test",
            synthetic=True,
            score=0.0,
            indicator_codes=["CHECK_UNAVAILABLE", "UNKNOWN_PSP_HANDLE"],
            status="INCONCLUSIVE",
            unavailable_checks=["lexical"],
        )
    ]
    rates = _indicator_rates(results)
    codes = {row["indicator_code"] for row in rates}
    assert "UNKNOWN_PSP_HANDLE" in codes
    assert "DOMAIN_VERY_NEW" in codes
    assert "CHECK_UNAVAILABLE" not in codes
