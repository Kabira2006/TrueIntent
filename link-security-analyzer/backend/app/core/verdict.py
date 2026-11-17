"""Verdict computation (Phase 8: delegated to scoring.py).

This module now wraps scoring.py for backward compatibility.
The Phase 1 skeleton scorer has been replaced with the complete weighted rule engine.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

from app.core.runner import CheckResult
from app.core.scoring import (
    Coverage,
    CoverageLevel,
    ScoringResult,
    Verdict,
    compute_coverage,
    score_scan,
)

# Re-export types for backward compatibility
__all__ = [
    "Verdict",
    "CoverageLevel",
    "Coverage",
    "compute_coverage",
    "compute_verdict",
    "RISK_SCORE_NOTE",
]

RISK_SCORE_NOTE = (
    "Heuristic risk score, not a probability. Do not display as a percentage."
)


def compute_verdict(
    results: Mapping[str, CheckResult],
    coverage: Coverage | None = None,
    *,
    registrable_domain: str | None = None,
) -> tuple[Verdict, int, list[str]]:
    """Return ``(verdict, risk_score, reason_ids)`` from check results.

    This is a compatibility wrapper around scoring.score_scan().
    For full scoring details, use scoring.score_scan() directly.

    Args:
        results: Check results from runner
        coverage: Optional pre-computed coverage (computed if None)
        registrable_domain: Domain for popularity override logic

    Returns:
        Tuple of (verdict, risk_score, reason_ids)
    """
    # Convert Mapping to dict if needed
    results_dict = dict(results) if not isinstance(results, dict) else results

    # Use new Phase 8 scorer
    scoring_result = score_scan(results_dict, registrable_domain=registrable_domain)

    # Extract reason IDs from top reasons
    reason_ids = [r["id"] for r in scoring_result.reasons]

    return scoring_result.verdict, scoring_result.risk_score, reason_ids
