"""Weight tuning helper for Phase 8.

Reports how verdicts change under weight tweaks on TRAIN portion of eval data.
Does NOT auto-tune on test set - that would be leakage.
Must manually review and update weights.yaml, then freeze before Phase 9 test evaluation.

Usage:
    python scripts/tune_weights.py --data data/eval/eval_manifest.csv --split train
"""

import argparse
import sys
from collections import Counter
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import yaml


def load_weights_config(weights_path: Path) -> dict:
    """Load current weights configuration."""
    with weights_path.open() as f:
        return yaml.safe_load(f)


def simulate_weight_change(
    signal_id: str,
    current_points: int,
    new_points: int,
    cases: list[dict],
) -> dict:
    """Simulate how verdict distribution changes with weight adjustment.

    Args:
        signal_id: Signal to adjust
        current_points: Current point value
        new_points: Proposed new point value
        cases: List of evaluation cases

    Returns:
        Dict with verdict changes
    """
    # This is a simplified simulation - in practice would need full scoring engine
    # For now, report what needs to be done
    
    delta = new_points - current_points
    
    affected_cases = [c for c in cases if signal_id in c.get("signals", [])]
    
    return {
        "signal_id": signal_id,
        "current_points": current_points,
        "new_points": new_points,
        "delta": delta,
        "affected_cases": len(affected_cases),
        "note": f"Would add {delta} points to {len(affected_cases)} cases",
    }


def analyze_signal_distribution(cases: list[dict]) -> dict:
    """Analyze signal frequency in training data.

    Returns signal hit counts and co-occurrence patterns.
    """
    signal_counts = Counter()
    verdict_by_signal = {}
    
    for case in cases:
        signals = case.get("signals", [])
        label = case.get("label")
        
        for sig in signals:
            sig_id = sig.get("id") if isinstance(sig, dict) else sig
            signal_counts[sig_id] += 1
            
            if sig_id not in verdict_by_signal:
                verdict_by_signal[sig_id] = {"benign": 0, "phishing": 0}
            
            if label in ["phishing", "malicious", "malware"]:
                verdict_by_signal[sig_id]["phishing"] += 1
            else:
                verdict_by_signal[sig_id]["benign"] += 1
    
    return {
        "signal_counts": signal_counts,
        "verdict_by_signal": verdict_by_signal,
    }


def generate_tuning_report(
    weights_config: dict,
    train_cases: list[dict],
    output_path: Path,
):
    """Generate tuning report showing current weights and distribution."""
    
    print("Analyzing training data...")
    distribution = analyze_signal_distribution(train_cases)
    
    signal_counts = distribution["signal_counts"]
    verdict_by_signal = distribution["verdict_by_signal"]
    
    # Build report
    report_lines = [
        "# Weight Tuning Report (Phase 8)",
        "",
        f"**Training cases analyzed:** {len(train_cases)}",
        f"**Unique signals found:** {len(signal_counts)}",
        "",
        "## Current Weights",
        "",
        "| Signal ID | Points | Severity | Phishing Cases | Benign Cases | Precision |",
        "|---|---|---|---|---|---|",
    ]
    
    signals_config = weights_config.get("signals", {})
    
    for sig_id, config in sorted(signals_config.items()):
        points = config.get("points", 0)
        severity = config.get("severity", "info")
        
        phishing = verdict_by_signal.get(sig_id, {}).get("phishing", 0)
        benign = verdict_by_signal.get(sig_id, {}).get("benign", 0)
        total = phishing + benign
        
        precision = f"{phishing / total * 100:.0f}%" if total > 0 else "N/A"
        
        report_lines.append(
            f"| `{sig_id}` | {points:+d} | {severity} | {phishing} | {benign} | {precision} |"
        )
    
    report_lines.extend([
        "",
        "## Recommendations",
        "",
        "### High false-positive signals (appear often in benign cases)",
        "",
    ])
    
    # Find signals that fire on benign cases frequently
    high_fp_signals = []
    for sig_id, verdicts in verdict_by_signal.items():
        benign = verdicts["benign"]
        phishing = verdicts["phishing"]
        total = benign + phishing
        
        if total >= 5 and benign / total > 0.3:  # >30% benign
            precision = phishing / total if total > 0 else 0
            current_points = signals_config.get(sig_id, {}).get("points", 0)
            high_fp_signals.append((sig_id, benign, phishing, precision, current_points))
    
    high_fp_signals.sort(key=lambda x: x[1], reverse=True)  # Sort by benign count
    
    if high_fp_signals:
        for sig_id, benign, phishing, precision, current_points in high_fp_signals[:10]:
            report_lines.append(
                f"- **`{sig_id}`**: {benign} benign, {phishing} phishing (precision: {precision:.1%}). "
                f"Current: {current_points:+d} points. Consider reducing if precision < 80%."
            )
    else:
        report_lines.append("- None identified (all signals have good precision)")
    
    report_lines.extend([
        "",
        "### Low-coverage signals (rarely fire)",
        "",
    ])
    
    rare_signals = [(sig_id, count) for sig_id, count in signal_counts.items() if count < 3]
    rare_signals.sort(key=lambda x: x[1])
    
    if rare_signals:
        for sig_id, count in rare_signals[:10]:
            current_points = signals_config.get(sig_id, {}).get("points", 0)
            report_lines.append(
                f"- **`{sig_id}`**: {count} cases. Current: {current_points:+d} points. "
                f"Verify this signal is still useful."
            )
    else:
        report_lines.append("- All signals have good coverage")
    
    report_lines.extend([
        "",
        "### Potential weight adjustments",
        "",
        "**Manual tuning process:**",
        "1. Review high false-positive signals above",
        "2. For each, check if precision < 80% and consider reducing points",
        "3. Update `weights.yaml` with new values",
        "4. Re-run golden tests: `pytest tests/test_golden_scoring.py`",
        "5. Re-run on validation set (NOT test set)",
        "6. Once satisfied, **freeze weights** before Phase 9 test evaluation",
        "",
        "**DO NOT tune on test set** - that would be leakage and invalidate evaluation.",
        "",
        "## Example Weight Changes (NOT automatic)",
        "",
    ])
    
    # Suggest a few example adjustments (do not apply automatically)
    examples = [
        ("HAS_PASSWORD_FIELD", 5, 3, "Reduce if appears on many benign sites"),
        ("DOMAIN_AGE_LT_30D", 20, 15, "Consider if new legit sites are flagged"),
        ("SUSPICIOUS_TLD", 15, 12, "Tune based on TLD distribution in data"),
    ]
    
    for sig_id, current, proposed, reason in examples:
        if sig_id in signals_config:
            report_lines.append(f"- `{sig_id}`: {current} → {proposed} points ({reason})")
    
    report_lines.extend([
        "",
        "---",
        "",
        "**Next steps:**",
        "1. Manually review this report",
        "2. Update weights.yaml based on findings",
        "3. Test on validation set",
        "4. Freeze before Phase 9 test evaluation",
    ])
    
    # Write report
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(report_lines))
    print(f"\nTuning report written to {output_path}")
    print(f"Analyzed {len(train_cases)} training cases")
    print(f"Found {len(signal_counts)} unique signals")


def main():
    parser = argparse.ArgumentParser(description="Weight tuning helper for Phase 8")
    parser.add_argument(
        "--weights",
        type=Path,
        default=Path(__file__).parent.parent / "app" / "core" / "weights.yaml",
        help="Path to weights.yaml",
    )
    parser.add_argument(
        "--data",
        type=Path,
        default=Path(__file__).parent.parent / "data" / "eval" / "eval_manifest.csv",
        help="Path to evaluation manifest (created in Phase 9)",
    )
    parser.add_argument(
        "--split",
        choices=["train", "val", "all"],
        default="train",
        help="Data split to analyze (train/val/all). Never use test for tuning!",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).parent / "tuning_report.md",
        help="Output path for tuning report",
    )
    
    args = parser.parse_args()
    
    # Load weights config
    if not args.weights.exists():
        print(f"Error: weights file not found: {args.weights}")
        sys.exit(1)
    
    weights_config = load_weights_config(args.weights)
    print(f"Loaded weights version: {weights_config.get('version', 'unknown')}")
    
    # Check if eval data exists (created in Phase 9)
    if not args.data.exists():
        print(f"Note: Evaluation data not found: {args.data}")
        print("This script will be fully functional in Phase 9 after eval set is created.")
        print("")
        print("For now, generating report based on weights configuration only...")
        
        # Generate basic report without training data
        output_lines = [
            "# Weight Tuning Report (Phase 8 - Pre-Evaluation)",
            "",
            "**Status:** Evaluation dataset not yet created (Phase 9)",
            "",
            "## Current Weights Summary",
            "",
            f"**Weights version:** {weights_config.get('version')}",
            f"**Total signals configured:** {len(weights_config.get('signals', {}))}",
            "",
            "### Signal distribution by severity",
            "",
        ]
        
        severity_counts = Counter()
        for sig_id, config in weights_config.get("signals", {}).items():
            severity = config.get("severity", "info")
            severity_counts[severity] += 1
        
        for severity, count in severity_counts.most_common():
            output_lines.append(f"- **{severity}:** {count} signals")
        
        output_lines.extend([
            "",
            "### Point distribution",
            "",
            "| Range | Count | Examples |",
            "|---|---|---|",
        ])
        
        by_points = {}
        for sig_id, config in weights_config.get("signals", {}).items():
            points = config.get("points", 0)
            by_points.setdefault(points, []).append(sig_id)
        
        for points in sorted(by_points.keys(), reverse=True):
            sigs = by_points[points]
            examples = ", ".join(f"`{s}`" for s in sigs[:3])
            if len(sigs) > 3:
                examples += f" (+{len(sigs) - 3} more)"
            output_lines.append(f"| {points:+d} | {len(sigs)} | {examples} |")
        
        output_lines.extend([
            "",
            "---",
            "",
            "**Next step:** Run Phase 9 to create evaluation dataset, then re-run this script.",
        ])
        
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text("\n".join(output_lines))
        print(f"\nBasic report written to {args.output}")
        return
    
    # Load training cases (Phase 9 will create this)
    import pandas as pd
    df = pd.read_csv(args.data)
    
    if args.split != "all":
        df = df[df["split"] == args.split]
    
    print(f"Loaded {len(df)} cases from {args.split} split")
    
    # Convert to list of dicts (simplified - Phase 9 will have full signal data)
    train_cases = df.to_dict("records")
    
    # Generate report
    generate_tuning_report(weights_config, train_cases, args.output)


if __name__ == "__main__":
    main()
