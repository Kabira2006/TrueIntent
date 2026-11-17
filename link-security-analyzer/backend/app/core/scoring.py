"""Phase 8: Explainable scoring engine with weighted rules and verdict policy.

Replaces the temporary skeleton scorer from Phase 1 with the complete rule engine
that implements all policies from spec section 9.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

from app.core.runner import CheckGroup, CheckResult

Verdict = Literal["DANGEROUS", "SUSPICIOUS", "LIKELY_SAFE", "UNKNOWN"]
CoverageLevel = Literal["low", "medium", "high"]

# Load configuration on module import
_CONFIG_DIR = Path(__file__).parent
_WEIGHTS_PATH = _CONFIG_DIR / "weights.yaml"
_REASONS_PATH = _CONFIG_DIR / "reasons.yaml"

with _WEIGHTS_PATH.open() as f:
    _WEIGHTS_CONFIG = yaml.safe_load(f)

with _REASONS_PATH.open() as f:
    _REASONS_CONFIG = yaml.safe_load(f)


@dataclass(frozen=True)
class WeightedSignal:
    """A signal with its weight configuration."""

    id: str
    points: int
    severity: str
    evidence: dict[str, Any]
    reason_text: str


@dataclass(frozen=True)
class Coverage:
    """Check coverage information."""

    completed: list[CheckGroup]
    unavailable: list[tuple[CheckGroup, str]]
    level: CoverageLevel
    completed_count: int
    total_count: int

    @property
    def complete_groups(self) -> list[str]:
        return [str(g) for g in self.completed]

    @property
    def missing_groups(self) -> list[dict[str, str]]:
        return [{"group": str(g), "reason": reason} for g, reason in self.unavailable]


@dataclass(frozen=True)
class ScoringResult:
    """Complete scoring result with verdict, reasons, and coverage."""

    verdict: Verdict
    risk_score: int
    reasons: list[dict[str, Any]]  # Top reasons for display
    all_signals: list[WeightedSignal]  # All signals for details
    coverage: Coverage
    advice: str
    versions: dict[str, Any]
    raw_score: int  # Before clamping
    applied_hard_override: bool
    applied_popularity_override: bool


ALL_GROUPS: tuple[CheckGroup, ...] = (
    "lexical",
    "reputation",
    "infrastructure",
    "external_reputation",
    "sandbox",
    "visual",
    "transaction",
)


def compute_coverage(results: dict[str, CheckResult]) -> Coverage:
    """Compute coverage from check results.

    A group counts as completed when at least one check in that group returned ok.
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

    return Coverage(
        completed=sorted(completed),
        unavailable=unavailable,
        level=level,
        completed_count=count,
        total_count=len(ALL_GROUPS),
    )


def _collect_signals(results: dict[str, CheckResult]) -> list[WeightedSignal]:
    """Collect all signals from check results and apply weights."""
    signals_config = _WEIGHTS_CONFIG["signals"]
    weighted: list[WeightedSignal] = []

    for result in results.values():
        for signal in result.signals:
            signal_id = signal.id
            config = signals_config.get(signal_id)

            if not config:
                # Unknown signal - skip (log warning in production)
                continue

            # Get reason text from reasons.yaml
            reason_template_id = config.get("reason", signal_id)
            reason_text = _render_reason(reason_template_id, signal.evidence or {})

            weighted.append(
                WeightedSignal(
                    id=signal_id,
                    points=config["points"],
                    severity=config["severity"],
                    evidence=signal.evidence or {},
                    reason_text=reason_text,
                )
            )

    return weighted


def _render_reason(reason_id: str, evidence: dict[str, Any]) -> str:
    """Render reason template with evidence placeholders."""
    reasons = _REASONS_CONFIG.get("reasons", {})
    reason_entry = reasons.get(reason_id)

    if not reason_entry:
        return f"Signal: {reason_id}"

    template = reason_entry.get("en", reason_id)

    # Simple template substitution (replace {key} with evidence[key])
    result = template
    for key, value in evidence.items():
        placeholder = f"{{{key}}}"
        if placeholder in result:
            result = result.replace(placeholder, str(value))

    return result


def _compute_raw_score(signals: list[WeightedSignal]) -> int:
    """Sum all signal points (including negatives)."""
    return sum(s.points for s in signals)


def _check_hard_override(signals: list[WeightedSignal]) -> bool:
    """Check if any hard override signal is present."""
    hard_overrides = set(_WEIGHTS_CONFIG.get("hard_overrides", []))
    return any(s.id in hard_overrides for s in signals)


def _check_popularity_override(
    signals: list[WeightedSignal],
    results: dict[str, CheckResult],
    registrable_domain: str | None,
) -> bool:
    """Check if popularity override should apply.

    Override applies if:
    - Domain in top-10k AND
    - No blocklist/GSB/VT hits AND
    - No cross-domain form AND
    - No brand mismatch AND
    - Not a shared hosting domain
    """
    if not registrable_domain:
        return False

    # Check if domain is shared hosting
    shared_suffixes = _WEIGHTS_CONFIG.get("shared_hosting_suffixes", [])
    if any(registrable_domain.endswith(suffix) for suffix in shared_suffixes):
        return False

    # Check if domain is in top-10k
    has_top_10k = any(s.id == "POPULARITY_TOP_10K" for s in signals)
    if not has_top_10k:
        return False

    # Check for blocking signals
    blocking_ids = set(_WEIGHTS_CONFIG["popularity_override"]["blocks_override"])
    has_blocking = any(s.id in blocking_ids for s in signals)

    return not has_blocking


def _apply_popularity_cap(score: int) -> int:
    """Cap score at configured maximum for popular domains."""
    max_score = _WEIGHTS_CONFIG["popularity_override"]["max_score_for_popular"]
    return min(score, max_score)


def _compute_verdict(
    score: int,
    coverage: Coverage,
    hard_override: bool,
) -> Verdict:
    """Compute verdict from score and coverage.

    Priority:
    1. Hard override -> DANGEROUS
    2. Score >= 70 -> DANGEROUS
    3. Score >= 35 -> SUSPICIOUS
    4. Score < 35 AND high coverage -> LIKELY_SAFE
    5. Otherwise -> UNKNOWN
    """
    if hard_override:
        return "DANGEROUS"

    thresholds = _WEIGHTS_CONFIG["thresholds"]
    dangerous_threshold = thresholds["dangerous"]
    suspicious_threshold = thresholds["suspicious"]

    if score >= dangerous_threshold:
        return "DANGEROUS"
    if score >= suspicious_threshold:
        return "SUSPICIOUS"

    # For LIKELY_SAFE, require minimum coverage per spec 9.3:
    # lexical + (popularity/feeds) + infrastructure + (sandbox OR top-100k)
    required_groups = {"lexical", "reputation", "infrastructure"}
    has_required = required_groups.issubset(set(coverage.complete_groups))

    # Need sandbox OR top-100k popularity
    has_sandbox = "sandbox" in coverage.complete_groups
    has_visual = "visual" in coverage.complete_groups

    # Check if we have sufficient coverage for LIKELY_SAFE
    # Minimum: lexical + reputation + infrastructure + (sandbox OR high popularity)
    if has_required and (has_sandbox or has_visual):
        return "LIKELY_SAFE"

    # Reduced coverage -> UNKNOWN
    return "UNKNOWN"


def _get_top_reasons(
    signals: list[WeightedSignal], max_count: int = 5
) -> list[dict[str, Any]]:
    """Get top N reasons sorted by points (descending), always include critical (severity=high)."""
    # Sort by points descending, then severity
    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    sorted_signals = sorted(
        signals,
        key=lambda s: (-abs(s.points), severity_order.get(s.severity, 3)),
    )

    # Always include high severity
    critical = [s for s in sorted_signals if s.severity == "high"]
    others = [s for s in sorted_signals if s.severity != "high"]

    # Take top N, ensuring all critical are included
    top = critical + others
    top = top[:max_count]

    return [
        {
            "id": s.id,
            "severity": s.severity,
            "text": s.reason_text,
            "evidence": s.evidence,
        }
        for s in top
    ]


def _get_advice(verdict: Verdict, coverage: Coverage) -> str:
    """Get advice text for verdict with coverage notes."""
    advice_config = _REASONS_CONFIG.get("advice", {})
    base_advice = advice_config.get(verdict, {}).get("en", "")

    # Add coverage notes for LIKELY_SAFE with reduced coverage
    if verdict == "LIKELY_SAFE":
        if "sandbox" not in coverage.complete_groups:
            note = _REASONS_CONFIG["coverage_note"]["sandbox_unavailable"]["en"]
            base_advice += f" {note}"
        elif "external_reputation" not in coverage.complete_groups:
            note = _REASONS_CONFIG["coverage_note"]["no_external_reputation"]["en"]
            base_advice += f" {note}"

    return base_advice


def score_scan(
    results: dict[str, CheckResult],
    *,
    registrable_domain: str | None = None,
) -> ScoringResult:
    """Compute complete scoring result from check results.

    Implements Phase 8 scoring policy per spec section 9:
    - Weighted signal accumulation
    - Hard overrides (blocklist, GSB, VT >= 3)
    - Popularity override (top-10k, no bad signals -> cap at 20)
    - Coverage-based verdict mapping
    - Top 5 reasons with critical always shown
    """
    # Step 1: Compute coverage
    coverage = compute_coverage(results)

    # Step 2: Collect and weight signals
    signals = _collect_signals(results)

    # Step 3: Compute raw score
    raw_score = _compute_raw_score(signals)

    # Step 4: Check hard override
    hard_override = _check_hard_override(signals)

    # Step 5: Check and apply popularity override
    popularity_override = _check_popularity_override(signals, results, registrable_domain)
    if popularity_override and not hard_override:
        score = _apply_popularity_cap(raw_score)
    else:
        score = raw_score

    # Step 6: Clamp to 0-100
    clamped_score = max(0, min(100, score))

    # Step 7: Compute verdict
    verdict = _compute_verdict(clamped_score, coverage, hard_override)

    # Step 8: Get top reasons
    top_reasons = _get_top_reasons(signals, max_count=5)

    # Step 9: Get advice
    advice = _get_advice(verdict, coverage)

    # Step 10: Build versions dict
    versions = {
        "rules": _WEIGHTS_CONFIG.get("version", "unknown"),
        "model": None,  # Phase 9
    }

    return ScoringResult(
        verdict=verdict,
        risk_score=clamped_score,
        reasons=top_reasons,
        all_signals=signals,
        coverage=coverage,
        advice=advice,
        versions=versions,
        raw_score=raw_score,
        applied_hard_override=hard_override,
        applied_popularity_override=popularity_override,
    )


def get_config_hash() -> str:
    """Return SHA-256 hash of weights + reasons config for cache invalidation."""
    weights_text = _WEIGHTS_PATH.read_text()
    reasons_text = _REASONS_PATH.read_text()
    combined = f"{weights_text}\n---\n{reasons_text}"
    return hashlib.sha256(combined.encode()).hexdigest()[:16]
