"""
Configuration module for Reconix Scan Engine.

Centralizes all application settings using pydantic-settings so that
configuration can be supplied via environment variables or a `.env`
file, with sensible defaults for local development.
"""

from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application-wide settings for Reconix Scan Engine."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # General
    app_name: str = "Reconix Scan Engine"
    environment: str = "development"
    debug: bool = True

    # Security / JWT
    secret_key: str = "insecure-dev-secret-change-me"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    # Database
    database_url: str = "sqlite+aiosqlite:///./reconix.db"

    # CORS
    allowed_origins: str = "http://localhost:5173,http://localhost:3000"

    # Crawler / scanner safety limits
    default_request_timeout_seconds: int = 10
    default_max_concurrent_requests: int = 5
    default_requests_per_second: int = 5
    default_max_crawl_depth: int = 3
    default_max_pages_per_scan: int = 200

    # Logging
    log_level: str = "INFO"
    audit_log_path: str = "./logs/audit.log"

    @property
    def cors_origins(self) -> List[str]:
        """Return the allowed CORS origins as a list of strings."""
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    """
    Return a cached Settings instance.

    Using lru_cache ensures the .env file and environment variables are
    only parsed once per process, while still allowing tests to override
    settings via dependency overrides if needed.
    """
    return Settings()


settings = get_settings()