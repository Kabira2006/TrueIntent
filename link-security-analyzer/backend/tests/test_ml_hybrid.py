"""Tests for hybrid scorer.

⚠️  UNTESTED - Created in Python 3.9 environment without dependencies.
    Must be validated in Docker with Python 3.11+ and full dependencies.
"""

import pytest

from app.ml.hybrid import hybrid_score, load_model


def test_hybrid_score_without_model():
    """Test hybrid scorer falls back to rules when model unavailable."""
    # Mock check results
    results = {
        "lexical": {
            "status": "ok",
            "signals": [
                {
                    "id": "TYPOSQUAT_BRAND",
                    "points": 35,
                    "severity": "high",
                    "explain": "Test typosquat",
                    "evidence": {},
                }
            ],
        },
        "reputation": {"status": "ok", "signals": []},
        "infrastructure": {"status": "unavailable", "reason": "offline", "signals": []},
    }
    
    result = hybrid_score(results, "evil.com", "https://evil.com")
    
    # Should fall back to rules-only
    assert result["hybrid_mode"] is False
    assert result["ml_probability"] is None
    assert result["versions"]["model"] is None


@pytest.mark.skip(reason="Requires trained model")
def test_hybrid_score_with_model():
    """Test hybrid scorer with ML model loaded."""
    # Would need model_b.joblib present
    pass


@pytest.mark.skip(reason="Requires trained model")
def test_ml_signal_added():
    """Test that ML_PHISH_PROBABILITY signal is added to results."""
    pass


def test_hard_override_preserved():
    """Test that hard overrides from rules are preserved in hybrid mode."""
    results = {
        "lexical": {"status": "ok", "signals": []},
        "reputation": {
            "status": "ok",
            "signals": [
                {
                    "id": "BLOCKLIST_URL_HIT",
                    "points": 100,
                    "severity": "critical",
                    "explain": "URL found in blocklist",
                    "evidence": {},
                }
            ],
        },
    }
    
    result = hybrid_score(results, "blocked.com", "https://blocked.com")
    
    # Hard override should force DANGEROUS regardless of ML
    assert result["verdict"] == "DANGEROUS"
    assert result["applied_hard_override"] is True
