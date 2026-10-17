"""Application settings loaded from environment variables.

A settings file (.env) is a private note on your own computer holding keys
and addresses, like a wallet. It is never committed to Git.
"""

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All backend knobs. Defaults match link-security-analyzer/.env.example."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = Field(default="postgresql+asyncpg://trueintent:trueintent@localhost:5432/trueintent")
    sync_database_url: str = Field(default="postgresql+psycopg2://trueintent:trueintent@localhost:5432/trueintent")
    redis_url: str = Field(default="redis://localhost:6379/0")

    gsb_api_key: str = Field(default="")
    vt_api_key: str = Field(default="")

    whois_timeout_seconds: float = Field(default=3.0)
    dns_timeout_seconds: float = Field(default=2.0)
    fast_path_budget_seconds: float = Field(default=5.0)
    sandbox_enabled: bool = Field(default=True)
    sandbox_page_timeout_seconds: int = Field(default=15)

    entropy_threshold: float = Field(default=4.5)
    entropy_min_length: int = Field(default=24)
    phash_distance_threshold: int = Field(default=10)

    rate_limit_scan_per_min: int = Field(default=20)
    rate_limit_get_per_min: int = Field(default=120)

    cors_origins: str = Field(default="http://localhost:3000")

    @field_validator("cors_origins")
    @classmethod
    def _strip_cors(cls, value: str) -> str:
        return value.strip()

    @property
    def cors_origins_list(self) -> list[str]:
        """Split the comma-separated CORS string into a clean list."""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached settings object (one per process)."""
    return Settings()
