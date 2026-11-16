"""Runner unit tests: every check is independent, timed, and never raises into the scan."""

import asyncio

import pytest

from app.core.runner import (
    CheckResult,
    CheckSpec,
    check,
    run_checks,
    spec_for,
)


@pytest.mark.asyncio
async def test_check_that_sleeps_beyond_timeout_becomes_unavailable_timeout():
    async def slow(_ctx):
        await asyncio.sleep(10)

    spec = CheckSpec(name="slow", fn=slow, timeout_s=0.01, group="lexical")
    results = await run_checks([spec], "ctx")
    result = results["slow"]
    assert result.status == "unavailable"
    assert result.reason == "timeout"
    assert result.group == "lexical"


@pytest.mark.asyncio
async def test_check_that_raises_becomes_unavailable_error():
    async def failing(_ctx):
        raise RuntimeError("boom")

    spec = CheckSpec(name="failing", fn=failing, timeout_s=1.0, group="infrastructure")
    results = await run_checks([spec], "ctx")
    result = results["failing"]
    assert result.status == "unavailable"
    assert result.reason == "error:RuntimeError"


@pytest.mark.asyncio
async def test_all_checks_unavailable_still_returns_results_for_every_check():
    async def slow(_ctx):
        await asyncio.sleep(10)

    async def failing(_ctx):
        raise ValueError("x")

    results = await run_checks(
        [
            CheckSpec(name="slow", fn=slow, timeout_s=0.01, group="lexical"),
            CheckSpec(
                name="failing", fn=failing, timeout_s=1.0, group="infrastructure"
            ),
        ],
        "ctx",
    )
    assert set(results) == {"slow", "failing"}
    assert all(r.status == "unavailable" for r in results.values())


@pytest.mark.asyncio
async def test_registered_check_runs_by_name():
    @check(name="registered_lexical", timeout_s=1.0, group="lexical")
    async def lexical(_ctx):
        return CheckResult(name="registered_lexical", status="ok")

    results = await run_checks(["registered_lexical"], "ctx")
    assert results["registered_lexical"].status == "ok"
    assert spec_for("registered_lexical").group == "lexical"


@pytest.mark.asyncio
async def test_concurrent_checks_finish_in_about_the_longest_time():
    async def one_second(_ctx):
        await asyncio.sleep(1)
        return CheckResult(name="one", status="ok")

    start = asyncio.get_running_loop().time()
    results = await run_checks(
        [
            CheckSpec(name=f"c{i}", fn=one_second, timeout_s=2.0, group="lexical")
            for i in range(5)
        ],
        "ctx",
    )
    elapsed = asyncio.get_running_loop().time() - start
    assert elapsed < 2.0  # concurrent, not sequential (5s)
    assert all(r.status == "ok" for r in results.values())


def test_check_result_is_a_dataclass_with_group():
    result = CheckResult(name="x", status="ok", group="lexical")
    assert result.name == "x"
    assert result.status == "ok"
    assert result.group == "lexical"
    assert result.signals == []


def test_signals_ordered_by_points_descending():
    from app.core.runner import Signal

    signals = [
        Signal(id="b", points=1, severity="low"),
        Signal(id="a", points=5, severity="high"),
        Signal(id="c", points=3, severity="medium"),
    ]
    ordered = sorted(signals, key=lambda s: -s.points)
    assert [s.id for s in ordered] == ["a", "c", "b"]
