"""Temporary verdict engine and coverage computation.

This module is Phase 1's *skeleton* scorer: it turns accumulated signals into a
numeric ``risk_score`` (0-100) and a verdict of ``DANGEROUS`` / ``SUSPICIOUS`` /
``LIKELY_SAFE`` / ``UNKNOWN``.  The real, weighted rule engine lands in Phase 8; this
skeleton exists so that every scan always returns a verdict with honest coverage
instead of "Inconclusive".

The numeric score is labelled a **heuristic risk score, not a probability** and is
never shown to users as a percentage.  The thresholds live here (not hard-coded
inline) so Phase 8 can replace this file wholesale.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from app.core.runner import CheckGroup, CheckResult

Verdict = Literal["DANGEROUS", "SUSPICIOUS", "LIKELY_SAFE", "UNKNOWN"]
CoverageLevel = Literal["low", "medium", "high"]

#: Signals that override every other input and force DANGEROUS.
#: Phase 8 will source these from weights.yaml; here they are named explicitly.
HARD_OVERRIDE_SIGNAL_IDS = frozenset(
    {
        "BLOCKLIST_URL_HIT",
        "GSB_THREAT",
        "VT_MALICIOUS_GE3",
    }
)

RISK_SCORE_NOTE = (
    "Heuristic risk score, not a probability. Do not display as a percentage."
)


@dataclass(frozen=True)
class VerdictConfig:
    """Thresholds for the temporary scorer."""

    dangerous_threshold: int = 70
    suspicious_threshold: int = 35

    def __post_init__(self) -> None:
        if not 0 <= self.suspicious_threshold <= self.dangerous_threshold <= 100:
            raise ValueError(
                "thresholds must satisfy 0 <= suspicious <= dangerous <= 100"
            )


@dataclass(frozen=True)
class Coverage:
    """What fraction of check groups actually ran."""

    completed: list[CheckGroup]
    unavailable: list[tuple[CheckGroup, str]]
    level: CoverageLevel

    @property
    def complete_groups(self) -> list[str]:
        return [g for g in self.completed]

    @property
    def missing_groups(self) -> list[dict[str, str]]:
        return [{"group": g, "reason": reason} for g, reason in self.unavailable]


ALL_GROUPS: tuple[CheckGroup, ...] = (
    "lexical",
    "reputation",
    "infrastructure",
    "external_reputation",
    "sandbox",
    "visual",
    "transaction",
)


def compute_coverage(
    results: Mapping[str, CheckResult],
) -> Coverage:
    """Compute coverage from check results.

    A group counts as completed only when *at least one* check in that group returned
    ``status == "ok"``.  Groups where every check is unavailable/skipped are listed as
    unavailable with their first reason.  Coverage level:

    * high  - all seven groups completed
    * medium - four or more groups completed
    * low   - fewer than four groups completed
    """
    completed: set[CheckGroup] = set()
    unavailable: list[tuple[CheckGroup, str]] = []
    by_group: dict[CheckGroup, list[CheckResult]] = {g: [] for g in ALL_GROUPS}
    for result in results.values():
        group = result.group
        if group is None:
            continue
        by_group.setdefault(group, []).append(result)

    for group in ALL_GROUPS:
        group_results = by_group.get(group, [])
        if not group_results:
            unavailable.append((group, "no_check_registered"))
            continue
        ok_results = [r for r in group_results if r.status == "ok"]
        if ok_results:
            completed.add(group)
        else:
            reason = group_results[0].reason or "unavailable"
            unavailable.append((group, reason))

    count = len(completed)
    if count == len(ALL_GROUPS):
        level: CoverageLevel = "high"
    elif count >= 4:
        level = "medium"
    else:
        level = "low"
    return Coverage(completed=sorted(completed), unavailable=unavailable, level=level)


def _sum_points(results: Mapping[str, CheckResult]) -> int:
    total = 0
    for result in results.values():
        for signal in result.signals:
            total += max(0, int(signal.points))
    return total


def compute_verdict(
    results: Mapping[str, CheckResult],
    coverage: Coverage,
    *,
    config: VerdictConfig | None = None,
) -> tuple[Verdict, int, list[str]]:
    """Return ``(verdict, risk_score, reason_ids)`` from check results.

    Order of precedence:

    1. Any hard-override signal -> ``DANGEROUS`` (score kept as computed).
    2. Score >= dangerous_threshold -> ``DANGEROUS``.
    3. Score >= suspicious_threshold -> ``SUSPICIOUS``.
    4. Score < suspicious_threshold and coverage is high -> ``LIKELY_SAFE``.
    5. Otherwise -> ``UNKNOWN`` (never Inconclusive: unavailable checks reduce
       confidence but never force a verdict of "I don't know").
    """
    config = config or VerdictConfig()
    score = min(100, max(0, _sum_points(results)))
    reason_ids: list[str] = sorted(
        {
            signal.id
            for result in results.values()
            for signal in result.signals
            if signal.id
        }
    )

    for result in results.values():
        for signal in result.signals:
            if signal.id in HARD_OVERRIDE_SIGNAL_IDS:
                return "DANGEROUS", score, reason_ids

    if score >= config.dangerous_threshold:
        return "DANGEROUS", score, reason_ids
    if score >= config.suspicious_threshold:
        return "SUSPICIOUS", score, reason_ids
    if coverage.level == "high":
        return "LIKELY_SAFE", score, reason_ids
    return "UNKNOWN", score, reason_ids
