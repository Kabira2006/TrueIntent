"""Run offline or online indicator and heuristic-score evaluation."""

import argparse
import asyncio
import csv
import hashlib
import importlib
import inspect
import json
import sys
from pathlib import Path
from typing import Any, Literal

from PIL import Image, ImageDraw
from pydantic import BaseModel, ConfigDict

EVAL_DIR = Path(__file__).resolve().parent
BACKEND_DIR = EVAL_DIR.parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.config import get_settings
from app.core.aggregator import build_report
from app.core.input_router import classify_input
from app.core.models import Indicator
from app.core.service import run_fast_path
from app.core.upi import analyze_upi

THRESHOLDS = (0.05, 0.10, 0.20, 0.30, 0.50, 0.75)
_EXCLUDED_HIT_CODES = {
    "CHECK_UNAVAILABLE",
    "DNS_LOOKUP_UNAVAILABLE",
    "INFRASTRUCTURE_UNAVAILABLE",
    "THREAT_FEED_UNAVAILABLE",
    "WHOIS_TIMEOUT_OR_UNAVAILABLE",
    "SANDBOX_UNAVAILABLE",
}
_KNOWN_INDICATOR_CODES = {
    "DOMAIN_VERY_NEW",
    "FAST_FLUX_LIKE",
    "FORM_POSTS_OVER_HTTP",
    "FORM_POSTS_TO_DIFFERENT_DOMAIN",
    "GSB_MATCH",
    "HIDDEN_IFRAME",
    "INVALID_VPA_FORMAT",
    "MALFORMED_UPI_URI",
    "META_REFRESH_REDIRECT",
    "MISSING_TRANSACTION_REF",
    "NEW_DOMAIN_LOGIN_FORM",
    "NON_INR_CURRENCY",
    "NO_A_RECORD",
    "NO_MX_RECORD",
    "PASSWORD_FIELD_PRESENT",
    "PAYEE_NAME_BRAND_MISMATCH",
    "PREFILLED_AMOUNT",
    "REDIRECT_CHAIN_LONG",
    "REDIRECT_CROSS_DOMAIN",
    "REDIRECT_TO_SHORTENER",
    "REGISTRAR_PRIVACY_PROXY",
    "SANDBOX_BLOCKED_REQUEST",
    "SANDBOX_BYTE_LIMIT_REACHED",
    "SENSITIVE_FIELD_REQUESTED",
    "SUSPICIOUS_NOTE_TEXT",
    "UNKNOWN_PSP_HANDLE",
    "UPI_COLLECT_REQUEST",
    "UPI_EMBEDDED_IN_WEB_URL",
    "VISUAL_BRAND_IMPERSONATION",
    "VISUAL_SIMILARITY_WEAK",
    "VT_MALICIOUS_VENDORS",
}


class EvalRow(BaseModel):
    model_config = ConfigDict(extra="ignore")

    row_id: str
    input: str
    label: Literal["malicious", "benign"]
    source: str = "unknown"
    synthetic: bool = False


class EvalResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    row_id: str
    input: str
    input_hash: str
    label: Literal["malicious", "benign"]
    source: str
    synthetic: bool
    score: float
    indicator_codes: list[str]
    status: str
    unavailable_checks: list[str]
    error_type: str | None = None


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--offline", action="store_true")
    mode.add_argument("--online", action="store_true")
    parser.add_argument("--dataset", type=Path)
    parser.add_argument("--output-dir", type=Path, default=EVAL_DIR / "results")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--rate-per-minute", type=int, default=4)
    parser.add_argument("--decision-threshold", type=float, default=0.30)
    parser.add_argument("--max-rows", type=int)
    return parser.parse_args(argv)


def read_dataset(path: Path) -> list[EvalRow]:
    with path.open(encoding="utf-8", newline="") as source:
        content = (line for line in source if not line.lstrip().startswith("#"))
        reader = csv.DictReader(content)
        return [EvalRow.model_validate(row) for row in reader]


def _input_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _offline_result(row: EvalRow) -> EvalResult:
    unavailable_codes: list[str] = []
    try:
        classification = classify_input(row.input)
    except (TypeError, ValueError) as error:
        return EvalResult(
            row_id=row.row_id,
            input=row.input,
            input_hash=_input_hash(row.input),
            label=row.label,
            source=row.source,
            synthetic=row.synthetic,
            score=0.0,
            indicator_codes=[],
            status="UNAVAILABLE",
            unavailable_checks=["input classification"],
            error_type=type(error).__name__,
        )

    payload = classification.embedded_payload or classification.normalized_payload
    scheme = payload.partition(":")[0].lower()
    is_web = scheme in {"http", "https"}
    lexical: dict[str, Any] = {"status": "NOT_APPLICABLE", "indicators": []}
    if is_web:
        try:
            lexical_checker = importlib.import_module("app.core.lexical").analyze_url
            lexical_result = lexical_checker(payload)
            if inspect.isawaitable(lexical_result):
                lexical_result = asyncio.run(lexical_result)
            lexical = _as_result(lexical_result)
        except (ImportError, AttributeError):
            lexical = _unavailable_result(
                "URL lexical analysis", reason="the analyzer module is missing"
            )
        except Exception as error:  # noqa: BLE001 - record unavailable analyzer facts
            lexical = _unavailable_result(
                "URL lexical analysis", reason=f"analyzer error {type(error).__name__}"
            )
            unavailable_codes.append(type(error).__name__)
        if lexical.get("status") == "UNAVAILABLE":
            unavailable_codes.append("URL lexical analysis")

    upi: dict[str, Any] = {"status": "NOT_APPLICABLE", "indicators": []}
    if scheme == "upi" or (is_web and _has_upi_query(payload)):
        try:
            upi = {"status": "AVAILABLE", **_as_result(analyze_upi(payload))}
        except (TypeError, ValueError) as error:
            upi = _unavailable_result(
                "UPI parsing", reason=f"parser error {type(error).__name__}"
            )
            unavailable_codes.append(type(error).__name__)

    infrastructure = (
        _unavailable_result("domain registration and DNS")
        if is_web
        else {"status": "NOT_APPLICABLE", "indicators": [], "features": {}}
    )
    feeds = (
        _unavailable_result("threat-feed lookup")
        if is_web
        else {"status": "NOT_APPLICABLE", "indicators": [], "features": {}}
    )
    report = build_report(
        lexical,
        infrastructure,
        feeds,
        upi if upi["status"] != "NOT_APPLICABLE" else None,
        None,
        payload_type=classification.payload_type,
        web_payload=is_web,
    )
    pillar_statuses = (
        report.technical_url_analysis.status,
        report.visual_brand_analysis.status,
        report.transaction_context_analysis.status,
    )
    for pillar_status in pillar_statuses:
        if pillar_status == "UNAVAILABLE":
            unavailable_codes.append(pillar_status)
    indicators = [
        *report.technical_url_analysis.indicators,
        *report.visual_brand_analysis.indicators,
        *report.transaction_context_analysis.indicators,
    ]
    return EvalResult(
        row_id=row.row_id,
        input=row.input,
        input_hash=_input_hash(row.input),
        label=row.label,
        source=row.source,
        synthetic=row.synthetic,
        score=report.heuristic_score,
        indicator_codes=sorted({item.code for item in indicators}),
        status=report.overall_indicator,
        unavailable_checks=sorted(set(unavailable_codes)),
    )


def _has_upi_query(url: str) -> bool:
    query = url.partition("?")[2].partition("#")[0].lower()
    return any(field.split("=", 1)[0] in {"pa", "pn"} for field in query.split("&"))


def _as_result(result: Any) -> dict[str, Any]:
    if isinstance(result, BaseModel):
        return result.model_dump(mode="python")
    if isinstance(result, dict):
        return result
    raise TypeError("analyzer returned an unsupported result")


def _unavailable_result(
    check_name: str, *, reason: str = "not run in offline mode"
) -> dict[str, Any]:
    indicator = Indicator(
        code="CHECK_UNAVAILABLE",
        severity="info",
        message=f"{check_name} is unavailable: {reason}.",
        evidence={"status": "UNAVAILABLE", "reason": reason},
    )
    return {
        "status": "UNAVAILABLE",
        "indicators": [indicator.model_dump(mode="python")],
        "features": {},
    }


async def _online_results(
    rows: list[EvalRow],
    *,
    progress_path: Path,
    resume: bool,
    rate_per_minute: int,
) -> list[EvalResult]:
    import redis.asyncio as redis
    from redis.exceptions import RedisError

    if not 1 <= rate_per_minute <= 4:
        raise ValueError("online scan rate must be between 1 and 4 per minute")
    progress_path.parent.mkdir(parents=True, exist_ok=True)
    stored = _read_progress(progress_path) if resume else {}
    previous = {
        _input_hash(row.input): stored[_input_hash(row.input)]
        for row in rows
        if _input_hash(row.input) in stored
        and _progress_matches(row, stored[_input_hash(row.input)])
    }
    remaining = _pending_rows(rows, previous)
    interval = 60.0 / rate_per_minute
    cache = redis.from_url(get_settings().redis_url)
    results = dict(previous)
    try:
        for index, row in enumerate(remaining):
            if index:
                await asyncio.sleep(interval)
            input_digest = _input_hash(row.input)
            try:
                scan = await run_fast_path(row.input, redis_client=cache)
                report = scan.advisory_report
                pillars = (
                    report.technical_url_analysis,
                    report.visual_brand_analysis,
                    report.transaction_context_analysis,
                )
                indicators = [item for pillar in pillars for item in pillar.indicators]
                result = EvalResult(
                    row_id=row.row_id,
                    input=row.input,
                    input_hash=input_digest,
                    label=row.label,
                    source=row.source,
                    synthetic=row.synthetic,
                    score=report.heuristic_score,
                    indicator_codes=sorted({item.code for item in indicators}),
                    status=report.overall_indicator,
                    unavailable_checks=[
                        pillar.status
                        for pillar in pillars
                        if pillar.status == "UNAVAILABLE"
                    ],
                )
            except (RedisError, OSError, TimeoutError, ValueError) as error:
                result = EvalResult(
                    row_id=row.row_id,
                    input=row.input,
                    input_hash=input_digest,
                    label=row.label,
                    source=row.source,
                    synthetic=row.synthetic,
                    score=0.0,
                    indicator_codes=[],
                    status="UNAVAILABLE",
                    unavailable_checks=["fast path"],
                    error_type=type(error).__name__,
                )
            results[input_digest] = result
            _append_progress(progress_path, result)
            print(f"Evaluated {len(results)}/{len(rows)} rows.")
    finally:
        try:
            await cache.aclose()
        except (RedisError, OSError):
            print("Redis connection close failed after evaluation.", file=sys.stderr)
    return [results[_input_hash(row.input)] for row in rows]


def _progress_matches(row: EvalRow, result: EvalResult) -> bool:
    return (
        result.row_id == row.row_id
        and result.label == row.label
        and result.source == row.source
        and result.synthetic == row.synthetic
    )


def _pending_rows(
    rows: list[EvalRow], completed: dict[str, EvalResult]
) -> list[EvalRow]:
    return [
        row
        for row in rows
        if _input_hash(row.input) not in completed
        or not _progress_matches(row, completed[_input_hash(row.input)])
    ]


def _read_progress(path: Path) -> dict[str, EvalResult]:
    if not path.exists():
        return {}
    completed: dict[str, EvalResult] = {}
    with path.open(encoding="utf-8") as source:
        for line in source:
            try:
                result = EvalResult.model_validate_json(line)
            except ValueError:
                continue
            completed[result.input_hash] = result
    return completed


def _append_progress(path: Path, result: EvalResult) -> None:
    with path.open("a", encoding="utf-8") as output:
        output.write(result.model_dump_json() + "\n")
        output.flush()


def _rate_metrics(
    results: list[EvalResult], threshold: float
) -> dict[str, float | int]:
    true_positive = sum(
        result.label == "malicious" and result.score >= threshold for result in results
    )
    false_positive = sum(
        result.label == "benign" and result.score >= threshold for result in results
    )
    false_negative = sum(
        result.label == "malicious" and result.score < threshold for result in results
    )
    true_negative = sum(
        result.label == "benign" and result.score < threshold for result in results
    )
    precision = (
        true_positive / (true_positive + false_positive)
        if true_positive + false_positive
        else 0.0
    )
    recall = (
        true_positive / (true_positive + false_negative)
        if true_positive + false_negative
        else 0.0
    )
    fpr = (
        false_positive / (false_positive + true_negative)
        if false_positive + true_negative
        else 0.0
    )
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "threshold": threshold,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "true_negative": true_negative,
    }


def _indicator_rates(results: list[EvalResult]) -> list[dict[str, Any]]:
    malicious = [result for result in results if result.label == "malicious"]
    benign = [result for result in results if result.label == "benign"]
    codes = sorted(
        (
            _KNOWN_INDICATOR_CODES
            | {code for result in results for code in result.indicator_codes}
        )
        - _EXCLUDED_HIT_CODES
    )
    return [
        {
            "indicator_code": code,
            "malicious_hits": sum(
                code in result.indicator_codes for result in malicious
            ),
            "malicious_total": len(malicious),
            "malicious_hit_rate": (
                sum(code in result.indicator_codes for result in malicious)
                / len(malicious)
                if malicious
                else 0.0
            ),
            "benign_hits": sum(code in result.indicator_codes for result in benign),
            "benign_total": len(benign),
            "benign_hit_rate": (
                sum(code in result.indicator_codes for result in benign) / len(benign)
                if benign
                else 0.0
            ),
        }
        for code in codes
    ]


def _write_csv(
    path: Path,
    rows: list[dict[str, Any]],
    *,
    fieldnames: list[str] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows and fieldnames is None:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fieldnames or list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _write_precision_recall_curve(path: Path, results: list[EvalResult]) -> None:
    image = Image.new("RGB", (900, 620), "white")
    draw = ImageDraw.Draw(image)
    left, top, right, bottom = 90, 45, 860, 530
    draw.line((left, top, left, bottom, right, bottom), fill="#334155", width=3)
    for step in range(6):
        x = left + (right - left) * step / 5
        y = bottom - (bottom - top) * step / 5
        draw.line((x, top, x, bottom), fill="#e2e8f0", width=1)
        draw.line((left, y, right, y), fill="#e2e8f0", width=1)
        draw.text((x - 8, bottom + 12), f"{step / 5:.1f}", fill="#0f172a")
        draw.text((left - 40, y - 5), f"{step / 5:.1f}", fill="#0f172a")
    points: list[tuple[float, float]] = []
    for threshold in sorted({0.0, *THRESHOLDS, 1.01}):
        metrics = _rate_metrics(results, threshold)
        points.append(
            (
                left + (right - left) * float(metrics["recall"]),
                bottom - (bottom - top) * float(metrics["precision"]),
            )
        )
    if len(points) > 1:
        draw.line(points, fill="#2563eb", width=4)
    for x, y in points:
        draw.ellipse((x - 4, y - 4, x + 4, y + 4), fill="#2563eb")
    draw.text((left, 10), "Precision-recall curve (threshold sweep)", fill="#0f172a")
    draw.text((right - 105, bottom + 36), "Recall", fill="#0f172a")
    draw.text((12, top - 20), "Precision", fill="#0f172a")
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, format="PNG")


def summarize(
    results: list[EvalResult],
    *,
    output_dir: Path,
    dataset_name: str,
    decision_threshold: float = 0.30,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    indicator_rates = _indicator_rates(results)
    threshold_metrics = [_rate_metrics(results, threshold) for threshold in THRESHOLDS]
    decision_metrics = _rate_metrics(results, decision_threshold)
    false_positives = sorted(
        (
            result
            for result in results
            if result.label == "benign" and result.score >= decision_threshold
        ),
        key=lambda result: result.score,
        reverse=True,
    )[:25]
    false_negatives = sorted(
        (
            result
            for result in results
            if result.label == "malicious" and result.score < decision_threshold
        ),
        key=lambda result: result.score,
    )[:25]
    _write_csv(
        output_dir / f"{dataset_name}_indicator_rates.csv",
        indicator_rates,
        fieldnames=[
            "indicator_code",
            "malicious_hits",
            "malicious_total",
            "malicious_hit_rate",
            "benign_hits",
            "benign_total",
            "benign_hit_rate",
        ],
    )
    _write_csv(
        output_dir / f"{dataset_name}_threshold_metrics.csv",
        threshold_metrics,
        fieldnames=[
            "threshold",
            "precision",
            "recall",
            "f1",
            "false_positive_rate",
            "true_positive",
            "false_positive",
            "false_negative",
            "true_negative",
        ],
    )
    for name, records in (
        ("false_positives", false_positives),
        ("false_negatives", false_negatives),
    ):
        _write_csv(
            output_dir / f"{dataset_name}_worst_{name}.csv",
            [
                {
                    "row_id": item.row_id,
                    "input": item.input,
                    "label": item.label,
                    "score": item.score,
                    "indicator_codes": ";".join(item.indicator_codes),
                    "source": item.source,
                    "synthetic": item.synthetic,
                }
                for item in records
            ],
            fieldnames=[
                "row_id",
                "input",
                "label",
                "score",
                "indicator_codes",
                "source",
                "synthetic",
            ],
        )
    _write_precision_recall_curve(
        output_dir / f"{dataset_name}_precision_recall.png", results
    )
    summary = {
        "dataset": dataset_name,
        "row_count": len(results),
        "malicious_count": sum(item.label == "malicious" for item in results),
        "benign_count": sum(item.label == "benign" for item in results),
        "synthetic_count": sum(item.synthetic for item in results),
        "unavailable_count": sum(bool(item.unavailable_checks) for item in results),
        "decision_threshold": decision_threshold,
        "decision_metrics": decision_metrics,
        "threshold_metrics": threshold_metrics,
        "indicator_rates": indicator_rates,
    }
    (output_dir / f"{dataset_name}_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    _print_summary(summary)
    return summary


def _print_summary(summary: dict[str, Any]) -> None:
    print(
        f"\n{summary['dataset']}: {summary['row_count']} rows "
        f"({summary['malicious_count']} malicious, {summary['benign_count']} benign; "
        f"{summary['synthetic_count']} synthetic; "
        f"{summary['unavailable_count']} with unavailable checks)"
    )
    print("Indicator | malicious hit rate | benign hit rate")
    for item in summary["indicator_rates"]:
        print(
            f"{item['indicator_code']} | "
            f"{item['malicious_hit_rate']:.3f} | {item['benign_hit_rate']:.3f}"
        )
    print("Threshold | precision | recall | F1 | false-positive rate")
    for item in summary["threshold_metrics"]:
        print(
            f"{item['threshold']:.2f} | {item['precision']:.3f} | "
            f"{item['recall']:.3f} | {item['f1']:.3f} | "
            f"{item['false_positive_rate']:.3f}"
        )


def _default_dataset(offline: bool) -> Path:
    locked = EVAL_DIR / "data" / "test_locked.csv"
    manual = EVAL_DIR / "data" / "india_manual.csv"
    if locked.exists():
        return locked
    if offline:
        print(
            "Locked external test split is absent; running only the labeled "
            "synthetic India set."
        )
        return manual
    raise FileNotFoundError(
        "The external locked split is missing. Build it before online evaluation."
    )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.rate_per_minute < 1 or args.rate_per_minute > 4:
        print("--rate-per-minute must be between 1 and 4.", file=sys.stderr)
        return 2
    if not 0.0 <= args.decision_threshold <= 1.0:
        print("--decision-threshold must be between 0 and 1.", file=sys.stderr)
        return 2
    dataset = args.dataset or _default_dataset(args.offline)
    try:
        rows = read_dataset(dataset)
    except (OSError, ValueError) as error:
        print(f"Could not read evaluation dataset: {error}", file=sys.stderr)
        return 1
    if args.max_rows is not None:
        if args.max_rows < 1:
            print("--max-rows must be positive.", file=sys.stderr)
            return 2
        rows = rows[: args.max_rows]
    if not rows:
        print("Evaluation dataset contains no rows.", file=sys.stderr)
        return 1

    dataset_name = (
        "india_manual_synthetic" if all(row.synthetic for row in rows) else dataset.stem
    )
    progress_path = EVAL_DIR / "data" / "raw" / f"{dataset_name}_online_progress.jsonl"
    try:
        if args.online:
            results = asyncio.run(
                _online_results(
                    rows,
                    progress_path=progress_path,
                    resume=args.resume,
                    rate_per_minute=args.rate_per_minute,
                )
            )
        else:
            results = [_offline_result(row) for row in rows]
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Evaluation stopped: {error}", file=sys.stderr)
        return 1
    summarize(
        results,
        output_dir=args.output_dir,
        dataset_name=dataset_name,
        decision_threshold=args.decision_threshold,
    )

    manual_path = EVAL_DIR / "data" / "india_manual.csv"
    if dataset.resolve() != manual_path.resolve() and manual_path.exists():
        manual_rows = read_dataset(manual_path)
        manual_results = [_offline_result(row) for row in manual_rows]
        summarize(
            manual_results,
            output_dir=args.output_dir,
            dataset_name="india_manual_synthetic",
            decision_threshold=args.decision_threshold,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
