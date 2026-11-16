"""Verdict engine tests: coverage levels and verdict mapping."""

from app.core.runner import CheckResult
from app.core.verdict import (
    VerdictConfig,
    compute_coverage,
    compute_verdict,
)


def _result(name, status="ok", group=None, signals=None, reason=None):
    return CheckResult(
        name=name,
        status=status,
        group=group,
        signals=signals or [],
        reason=reason,
    )


def test_coverage_level_high_when_all_groups_complete():
    results = {
        g: _result(g, "ok", g)
        for g in (
            "lexical",
            "reputation",
            "infrastructure",
            "external_reputation",
            "sandbox",
            "visual",
            "transaction",
        )
    }
    coverage = compute_coverage(results)
    assert coverage.level == "high"
    assert len(coverage.completed) == 7


def test_coverage_level_medium_when_four_groups_complete():
    results = {
        g: _result(g, "ok", g)
        for g in ("lexical", "reputation", "infrastructure", "external_reputation")
    }
    coverage = compute_coverage(results)
    assert coverage.level == "medium"
    assert len(coverage.missing_groups) == 3


def test_coverage_level_low_when_fewer_than_four_complete():
    results = {"lexical": _result("lexical", "ok", "lexical")}
    coverage = compute_coverage(results)
    assert coverage.level == "low"


def test_all_unavailable_yields_low_coverage_with_reasons():
    results = {
        g: _result(g, "unavailable", g, reason="timeout")
        for g in ("lexical", "infrastructure")
    }
    coverage = compute_coverage(results)
    assert coverage.level == "low"
    assert len(coverage.missing_groups) == 7  # all 7 groups are missing or unavailable


def test_hard_override_force_dangerous():
    results = {
        "lexical": _result(
            "lexical",
            "ok",
            "lexical",
            signals=[type("S", (), {"id": "BLOCKLIST_URL_HIT", "points": 100})()],
        )
    }
    coverage = compute_coverage(results)
    verdict, _score, _reason_ids = compute_verdict(results, coverage)
    assert verdict == "DANGEROUS"


def test_score_above_dangerous_threshold_is_dangerous():
    results = {
        "lexical": _result(
            "lexical",
            "ok",
            "lexical",
            signals=[type("S", (), {"id": "SIG", "points": 80})()],
        )
    }
    coverage = compute_coverage(results)
    verdict, score, _ = compute_verdict(results, coverage)
    assert verdict == "DANGEROUS"
    assert score == 80


def test_score_between_thresholds_is_suspicious():
    results = {
        "lexical": _result(
            "lexical",
            "ok",
            "lexical",
            signals=[type("S", (), {"id": "SIG", "points": 50})()],
        )
    }
    coverage = compute_coverage(results)
    verdict, score, _ = compute_verdict(results, coverage)
    assert verdict == "SUSPICIOUS"
    assert score == 50


def test_low_coverage_below_threshold_is_unknown_not_inconclusive():
    results = {
        "lexical": _result(
            "lexical",
            "ok",
            "lexical",
            signals=[type("S", (), {"id": "SIG", "points": 10})()],
        )
    }
    coverage = compute_coverage(results)  # low
    verdict, score, _ = compute_verdict(results, coverage)
    assert verdict == "UNKNOWN"
    assert score == 10


def test_high_coverage_below_suspicious_threshold_is_likely_safe():
    results = {
        g: _result(g, "ok", g)
        for g in (
            "lexical",
            "reputation",
            "infrastructure",
            "external_reputation",
            "sandbox",
            "visual",
            "transaction",
        )
    }
    results["lexical"].signals = [type("S", (), {"id": "SIG", "points": 5})()]
    coverage = compute_coverage(results)
    verdict, _score, _ = compute_verdict(results, coverage)
    assert verdict == "LIKELY_SAFE"
    assert coverage.level == "high"


def test_thresholds_are_configurable_not_hardcoded():
    config = VerdictConfig(dangerous_threshold=50, suspicious_threshold=20)
    results = {
        "lexical": _result(
            "lexical",
            "ok",
            "lexical",
            signals=[type("S", (), {"id": "SIG", "points": 30})()],
        )
    }
    coverage = compute_coverage(results)
    verdict, _score, _ = compute_verdict(results, coverage, config=config)
    assert verdict == "SUSPICIOUS"  # 30 >= 20 suspicious but < 50 dangerous


def test_risk_score_note_is_not_a_probability():
    from app.core.verdict import RISK_SCORE_NOTE

    assert "not a probability" in RISK_SCORE_NOTE
