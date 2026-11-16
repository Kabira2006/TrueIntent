"""Bounded check runner: every check is independent, timed, and never raises into the scan.

A *check* is an async callable ``fn(ctx)`` that returns either a :class:`CheckResult`
or a plain mapping with keys ``status``/``signals``/``detail``/``reason``.  The runner
runs checks concurrently, wraps each in its own timeout (``asyncio.wait_for``), and
converts every exception - including ``CancelledError`` from a timeout - into an
``unavailable`` result with a reason such as ``"timeout"`` or ``"error:<Name>"``.  A
single failing check can never make the whole scan fail or become "Inconclusive".

Use the :func:`check` decorator to register a check under a name with a timeout and a
group (one of ``lexical``, ``reputation``, ``infrastructure``, ``external_reputation``,
``sandbox``, ``visual``, ``transaction``).  Registered checks are run by name with
:func:`run_checks`.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

CheckStatus = Literal["ok", "unavailable", "skipped"]
CheckGroup = Literal[
    "lexical",
    "reputation",
    "infrastructure",
    "external_reputation",
    "sandbox",
    "visual",
    "transaction",
]


@dataclass
class Signal:
    """One explainable fact detected by a check."""

    id: str
    points: int
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    explain: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckResult:
    """Outcome of one bounded check."""

    name: str
    status: CheckStatus
    group: CheckGroup | None = None
    signals: list[Signal] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)
    reason: str | None = None
    took_ms: int = 0


@dataclass
class CheckSpec:
    """A registered check: the coroutine, its per-check timeout, and its group."""

    name: str
    fn: Callable[[Any], Awaitable[Any]]
    timeout_s: float
    group: CheckGroup


_REGISTRY: dict[str, CheckSpec] = {}


def check(name: str, timeout_s: float, group: CheckGroup):
    """Register an async check under ``name`` with a timeout and a group."""

    def decorator(
        fn: Callable[[Any], Awaitable[Any]],
    ) -> Callable[[Any], Awaitable[Any]]:
        _REGISTRY[name] = CheckSpec(name, fn, float(timeout_s), group)
        return fn

    return decorator


def registered_checks() -> list[str]:
    """Return the names of all registered checks, in registration order."""
    return list(_REGISTRY)


def spec_for(name: str) -> CheckSpec:
    """Return the registered :class:`CheckSpec` for ``name`` (KeyError if absent)."""
    return _REGISTRY[name]


def _to_signal(item: Any) -> Signal:
    if isinstance(item, Signal):
        return item
    if isinstance(item, Mapping):
        return Signal(
            id=str(item.get("id", item.get("code", ""))),
            points=int(item.get("points", 0)),
            severity=item.get("severity", "info"),
            explain=str(item.get("explain", item.get("message", ""))),
            evidence=dict(item.get("evidence", item.get("detail", {}))),
        )
    return Signal(
        id=str(getattr(item, "code", "")),
        points=int(getattr(item, "points", 0)),
        severity=str(getattr(item, "severity", "info")),
        explain=str(getattr(item, "explain", getattr(item, "message", ""))),
        evidence=dict(getattr(item, "evidence", {})),
    )


def _coerce_result(
    name: str, outcome: Any, took_ms: int, group: CheckGroup | None = None
) -> CheckResult:
    """Normalize a check's return value into a :class:`CheckResult`."""
    if isinstance(outcome, CheckResult):
        return CheckResult(
            name,
            outcome.status,
            group or outcome.group,
            list(outcome.signals),
            dict(outcome.detail),
            outcome.reason,
            outcome.took_ms or took_ms,
        )
    if isinstance(outcome, Mapping):
        status = outcome.get("status", "ok")
        if status not in ("ok", "unavailable", "skipped"):
            status = "ok"
        signals = [
            _to_signal(item)
            for item in (outcome.get("signals", outcome.get("indicators", [])) or [])
        ]
        preserved: dict[str, Any] = {}
        for key, value in outcome.items():
            if key in (
                "status",
                "signals",
                "indicators",
                "detail",
                "reason",
                "took_ms",
            ):
                continue
            preserved[key] = value
        detail: dict[str, Any] = dict(outcome.get("detail", {}))
        detail.update(preserved)
        return CheckResult(
            name,  # type: ignore[arg-type]
            status,
            group,
            signals=signals,
            detail=detail,
            reason=outcome.get("reason"),
            took_ms=took_ms,
        )
    if hasattr(outcome, "indicators") or hasattr(outcome, "features"):
        signals = [
            _to_signal(item) for item in (getattr(outcome, "indicators", []) or [])
        ]
        return CheckResult(
            name,
            "ok",
            group,
            signals=signals,
            detail=dict(getattr(outcome, "features", {})),
            took_ms=took_ms,
        )
    return CheckResult(name, "ok", group, detail={"raw": outcome}, took_ms=took_ms)


async def _run_one(spec: CheckSpec, ctx: Any) -> CheckResult:
    """Run one check within its own timeout; never raise into the caller."""
    t0 = time.monotonic()
    try:
        outcome = await asyncio.wait_for(spec.fn(ctx), timeout=spec.timeout_s)
    except asyncio.CancelledError:
        return CheckResult(
            spec.name,
            "unavailable",
            spec.group,
            reason="timeout",
            took_ms=int((time.monotonic() - t0) * 1000),
        )
    except TimeoutError:
        return CheckResult(
            spec.name,
            "unavailable",
            spec.group,
            reason="timeout",
            took_ms=int((time.monotonic() - t0) * 1000),
        )
    except Exception as error:  # noqa: BLE001 - a failing check never breaks the scan
        return CheckResult(
            spec.name,
            "unavailable",
            spec.group,
            reason=f"error:{type(error).__name__}",
            took_ms=int((time.monotonic() - t0) * 1000),
        )
    return _coerce_result(
        spec.name,
        outcome,
        int((time.monotonic() - t0) * 1000),
        group=spec.group,
    )


async def run_checks(checks: list[str | CheckSpec], ctx: Any) -> dict[str, CheckResult]:
    """Run checks concurrently, each bounded by its own timeout."""
    specs: list[CheckSpec] = []
    for item in checks:
        if isinstance(item, str):
            specs.append(spec_for(item))
        else:
            specs.append(item)

    outcomes = await asyncio.gather(*(_run_one(spec, ctx) for spec in specs))
    return {spec.name: result for spec, result in zip(specs, outcomes)}
