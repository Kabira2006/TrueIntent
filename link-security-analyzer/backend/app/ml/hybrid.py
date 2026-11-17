"""Hybrid scorer: combines rule-based verdict with ML probability.

Loads model_b.joblib and adds ML_PHISH_PROBABILITY signal.
Falls back to rules-only if model file missing (resilience).

The combination strategy (weighted average, max-with-veto, etc.) is chosen
on the VALIDATION split during training and recorded in model metadata.
"""

from __future__ import annotations

import logging
import pickle
from pathlib import Path
from typing import Any, Optional

from app.core.brands import load_brand_catalog
from app.core.scoring import score_scan
from app.ml.features import extract_features

logger = logging.getLogger(__name__)

# Model path
MODEL_PATH = Path(__file__).parent / "model_b.joblib"

# Global model cache (loaded once at startup)
_model_cache: Optional[dict[str, Any]] = None


def load_model() -> Optional[dict[str, Any]]:
    """Load trained model from disk. Returns None if not available."""
    global _model_cache
    
    if _model_cache is not None:
        return _model_cache
    
    if not MODEL_PATH.exists():
        logger.warning(f"ML model not found at {MODEL_PATH}. Falling back to rules-only.")
        return None
    
    try:
        with open(MODEL_PATH, "rb") as f:
            model_package = pickle.load(f)
        
        logger.info(f"Loaded ML model: {model_package['metadata']['model_name']}")
        logger.info(f"Trained at: {model_package['metadata']['trained_at']}")
        logger.info(f"Val AUC: {model_package['metadata']['val_auc']:.4f}")
        
        _model_cache = model_package
        return _model_cache
    
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        return None


def predict_ml_probability(url: str, infrastructure_data: Optional[dict[str, Any]] = None) -> Optional[float]:
    """Predict phishing probability using ML model.
    
    Returns:
        Probability [0, 1] or None if model unavailable.
    """
    model_package = load_model()
    if model_package is None:
        return None
    
    model = model_package["model"]
    feature_columns = model_package["feature_columns"]
    
    try:
        catalog = load_brand_catalog()
        features = extract_features(
            url,
            catalog=catalog,
            infrastructure_data=infrastructure_data,
            offline_mode=infrastructure_data is None,
        )
        
        # Extract feature values in correct order
        X = [features.get(col, 0) for col in feature_columns]
        
        # Predict probability
        proba = model.predict_proba([X])[0][1]  # Probability of class 1 (phishing)
        
        return float(proba)
    
    except Exception as e:
        logger.error(f"ML prediction failed: {e}")
        return None


def hybrid_score(
    results: dict[str, Any],
    registrable_domain: str,
    url: str,
    infrastructure_data: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Compute hybrid score: rules + ML.
    
    Strategy (chosen on VAL split during training):
    - If ML available: weighted average (0.6 * rules + 0.4 * ML)
    - Hard overrides and popularity override still apply (from rules)
    - If ML unavailable: rules-only
    
    Args:
        results: Check results dict (from runner)
        registrable_domain: Registrable domain for popularity override
        url: Original URL for ML feature extraction
        infrastructure_data: Infrastructure check results for ML features
    
    Returns:
        ScoringResult dict with verdict, risk_score, reasons, etc.
        Includes 'ml_probability' and 'versions.model' fields.
    """
    # Get rules-based score
    rules_result = score_scan(results, registrable_domain)
    
    # Try ML prediction
    ml_proba = predict_ml_probability(url, infrastructure_data)
    
    if ml_proba is None:
        # Model unavailable: rules-only
        rules_result["ml_probability"] = None
        rules_result["versions"]["model"] = None
        rules_result["hybrid_mode"] = False
        return rules_result
    
    # Add ML signal to results
    ml_signal = {
        "id": "ML_PHISH_PROBABILITY",
        "points": int((ml_proba - 0.5) * 100),  # Scale to [-50, +50]
        "severity": "high" if ml_proba > 0.8 else "medium",
        "explain": f"Machine learning model estimates {ml_proba*100:.1f}% phishing probability.",
        "evidence": {"ml_probability": round(ml_proba, 4)},
    }
    
    # Combine scores: weighted average
    # Strategy: 60% rules, 40% ML (chosen on VAL split)
    rules_score = rules_result["raw_score"]
    ml_score = ml_proba * 100  # Scale to [0, 100]
    
    combined_raw = 0.6 * rules_score + 0.4 * ml_score
    
    # Apply same hard overrides and popularity override as rules
    # (Hard overrides take precedence)
    if rules_result["applied_hard_override"]:
        # Hard override: keep rules decision
        final_score = rules_result["risk_score"]
        verdict = "DANGEROUS"
    elif rules_result["applied_popularity_override"]:
        # Popularity override: cap at 20
        final_score = min(20, max(0, combined_raw))
        verdict = _map_score_to_verdict(final_score, rules_result["coverage"])
    else:
        # Normal case: use combined score
        final_score = max(0, min(100, combined_raw))
        verdict = _map_score_to_verdict(final_score, rules_result["coverage"])
    
    # Add ML signal to reasons
    all_signals = rules_result["all_signals"] + [ml_signal]
    
    # Re-rank reasons (top 5 by points)
    all_signals_sorted = sorted(
        all_signals,
        key=lambda s: (abs(s["points"]), {"high": 3, "medium": 2, "low": 1, "info": 0}.get(s["severity"], 0)),
        reverse=True,
    )
    top_reasons = []
    for sig in all_signals_sorted[:5]:
        top_reasons.append({
            "id": sig["id"],
            "severity": sig["severity"],
            "text": sig["explain"],
            "evidence": sig.get("evidence", {}),
        })
    
    # Build hybrid result
    hybrid_result = {
        **rules_result,
        "verdict": verdict,
        "risk_score": int(final_score),
        "raw_score": combined_raw,
        "ml_probability": round(ml_proba, 4),
        "rules_score": rules_score,
        "ml_score": ml_score,
        "hybrid_mode": True,
        "reasons": top_reasons,
        "all_signals": all_signals,
        "versions": {
            **rules_result["versions"],
            "model": load_model()["metadata"]["model_name"] if load_model() else None,
        },
    }
    
    return hybrid_result


def _map_score_to_verdict(score: float, coverage: dict[str, Any]) -> str:
    """Map risk score to verdict (same logic as scoring.py)."""
    if score >= 70:
        return "DANGEROUS"
    elif score >= 35:
        return "SUSPICIOUS"
    else:
        # Check coverage for LIKELY_SAFE
        completed = coverage.get("completed", [])
        has_lexical = "lexical" in completed
        has_reputation = "reputation" in completed
        has_infra = "infrastructure" in completed
        has_sandbox = "sandbox" in completed or "transaction" in completed
        
        # Minimum coverage: lexical + reputation + infrastructure + sandbox
        if has_lexical and has_reputation and has_infra and has_sandbox:
            return "LIKELY_SAFE"
        else:
            return "UNKNOWN"
