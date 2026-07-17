from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional, Any
import secrets
import json


class Settings(BaseSettings):
    # ─────────────────────────────────────────────────────
    # App
    # ─────────────────────────────────────────────────────
    APP_NAME: str = "SentinelX"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # ─────────────────────────────────────────────────────
    # Security
    # ─────────────────────────────────────────────────────
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ─────────────────────────────────────────────────────
    # Database
    # ─────────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite+aiosqlite:///./sentinelx.db"

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def convert_database_url(cls, v: Any) -> Any:
        if isinstance(v, str):
            # Render PostgreSQL URLs
            if v.startswith("postgres://"):
                v = v.replace("postgres://", "postgresql+asyncpg://", 1)
            elif (
                v.startswith("postgresql://")
                and not v.startswith("postgresql+asyncpg://")
            ):
                v = v.replace("postgresql://", "postgresql+asyncpg://", 1)
        return v

    # ─────────────────────────────────────────────────────
    # External APIs
    # ─────────────────────────────────────────────────────
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    OTX_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None

    # ─────────────────────────────────────────────────────
    # Email
    # ─────────────────────────────────────────────────────
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASS: Optional[str] = None

    # Slack
    SLACK_WEBHOOK_URL: Optional[str] = None

    # Telegram
    TELEGRAM_BOT_TOKEN: Optional[str] = None
    TELEGRAM_CHAT_ID: Optional[str] = None

    # Discord
    DISCORD_WEBHOOK_URL: Optional[str] = None

    # Microsoft Teams
    TEAMS_WEBHOOK_URL: Optional[str] = None

    # Shodan
    SHODAN_API_KEY: Optional[str] = None

    # ─────────────────────────────────────────────────────
    # CORS
    # ─────────────────────────────────────────────────────
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:8080",
        "https://sentinelx-frontend-yx15.onrender.com",
    ]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Any) -> Any:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                try:
                    return json.loads(v)
                except Exception:
                    pass

            return [origin.strip() for origin in v.split(",") if origin.strip()]

        return v

    # ─────────────────────────────────────────────────────
    # Pagination
    # ─────────────────────────────────────────────────────
    DEFAULT_PAGE_SIZE: int = 50
    MAX_PAGE_SIZE: int = 500

    # ─────────────────────────────────────────────────────
    # Detection
    # ─────────────────────────────────────────────────────
    MAX_EVENTS_PER_SECOND: int = 10000
    ALERT_RETENTION_DAYS: int = 90
    LOG_RETENTION_DAYS: int = 365

    # ─────────────────────────────────────────────────────
    # Rate Limiting
    # ─────────────────────────────────────────────────────
    RATE_LIMIT_DEFAULT: str = "100/minute"
    RATE_LIMIT_AUTH: str = "10/minute"

    # ─────────────────────────────────────────────────────
    # Settings
    # ─────────────────────────────────────────────────────
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
