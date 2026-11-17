"""Tests for ML feature extraction.

⚠️  UNTESTED - Created in Python 3.9 environment without dependencies.
    Must be validated in Docker with Python 3.11+ and full dependencies.
"""

import pytest

from app.ml.features import extract_features, FEATURE_COLUMNS_HOST_ONLY


def test_extract_features_minimal():
    """Test feature extraction for simple URL."""
    features = extract_features("https://example.com", offline_mode=True)
    
    assert "url_len" in features
    assert "host_len" in features
    assert "entropy" in features
    assert features["is_https"] == 1
    assert features["offline_mode"] == 1


def test_extract_features_with_infrastructure():
    """Test feature extraction with infrastructure data."""
    infra_data = {
        "domain_age_days": 30,
        "dns_resolves": True,
        "mx_present": False,
        "tls_age_days": 10,
    }
    
    features = extract_features("https://newsite.com", infrastructure_data=infra_data)
    
    assert features["domain_age_days"] == 30
    assert features["domain_age_missing"] == 0
    assert features["domain_age_lt_30"] == 0  # exactly 30
    assert features["dns_resolves"] == 1
    assert features["tls_age_lt_7"] == 0  # 10 days


def test_feature_columns_complete():
    """Test that all required feature columns are present."""
    features = extract_features("https://test.com/path", offline_mode=True)
    
    for col in FEATURE_COLUMNS_HOST_ONLY:
        assert col in features, f"Missing feature column: {col}"


def test_missing_features_tracked():
    """Test that missing features are tracked."""
    features = extract_features("https://test.com", offline_mode=True)
    
    assert "missing_features" in features
    assert isinstance(features["missing_features"], list)
    # In offline mode, infrastructure features should be missing
    assert "domain_age" in features["missing_features"]


@pytest.mark.skip(reason="Requires brand catalog fixture")
def test_typosquat_feature():
    """Test typosquat signal detection in features."""
    # Would need brand catalog loaded
    pass
