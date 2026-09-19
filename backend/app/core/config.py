"""
HashLens Configuration Module
Centralized Pydantic-based settings with environment variable overrides.
"""

from pathlib import Path
from typing import List, Optional, Union
from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application metadata
    APP_NAME: str = "HashLens"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = "development"
    DEBUG: bool = False

    # Server binding
    API_HOST: str = "0.0.0.0"
    API_PORT: int = Field(default=8000, validation_alias=AliasChoices("PORT", "API_PORT"))
    API_V1_PREFIX: str = "/api/v1"
    API_URL: Optional[str] = None

    # Security & I/O limits
    MAX_UPLOAD_SIZE: int = 100 * 1024 * 1024  # 100 MB default max upload
    DEFAULT_CHUNK_SIZE: int = 1024 * 1024     # 1 MB default chunk size
    MIN_CHUNK_SIZE: int = 4096                # 4 KB minimum chunk size
    MAX_CHUNK_SIZE: int = 16 * 1024 * 1024    # 16 MB maximum chunk size

    # Rate Limiting (in-memory token bucket/sliding window)
    RATE_LIMIT_REQUESTS: int = 120
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # Security Headers
    ENABLE_HSTS: bool = False

    # CORS
    ALLOWED_ORIGINS: Union[str, List[str]] = [
        "http://localhost:8501",
        "http://127.0.0.1:8501",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

    # Persistence
    DATABASE_URL: str = "sqlite:///./data/hashlens.db"

    # Logging
    LOG_LEVEL: str = "INFO"

    # Directory Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    TEMP_DIR: Path = BASE_DIR / "temp"
    REPORTS_DIR: Path = BASE_DIR / "data" / "reports"

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_allowed_origins(cls, value: Union[str, List[str]]) -> List[str]:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    def ensure_directories(self) -> None:
        """Ensure necessary runtime directories exist."""
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.TEMP_DIR.mkdir(parents=True, exist_ok=True)
        self.REPORTS_DIR.mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_directories()
