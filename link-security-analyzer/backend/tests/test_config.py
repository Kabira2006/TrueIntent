"""Unit tests for app.config. No network, Redis, or Postgres touched."""

from pytest import MonkeyPatch

from app.config import Settings, get_settings


def test_defaults_match_env_example() -> None:
    settings = Settings(_env_file=None)
    assert settings.whois_timeout_seconds == 3.0
    assert settings.dns_timeout_seconds == 2.0
    assert settings.fast_path_budget_seconds == 5.0
    assert settings.sandbox_enabled is True
    assert settings.sandbox_page_timeout_seconds == 15
    assert settings.entropy_threshold == 4.5
    assert settings.entropy_min_length == 24
    assert settings.phash_distance_threshold == 10
    assert settings.rate_limit_scan_per_min == 20
    assert settings.rate_limit_get_per_min == 120
    assert settings.cors_origins_list == ["http://localhost:3000"]


def test_env_overrides(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("WHOIS_TIMEOUT_SECONDS", "9.5")
    monkeypatch.setenv("SANDBOX_ENABLED", "false")
    monkeypatch.setenv("CORS_ORIGINS", "http://a.example, http://b.example ")
    get_settings.cache_clear()
    try:
        settings = get_settings()
        assert settings.whois_timeout_seconds == 9.5
        assert settings.sandbox_enabled is False
        assert settings.cors_origins_list == ["http://a.example", "http://b.example"]
    finally:
        get_settings.cache_clear()


def test_secrets_default_to_empty() -> None:
    settings = Settings(_env_file=None)
    assert settings.gsb_api_key == ""
    assert settings.vt_api_key == ""
