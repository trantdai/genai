"""Application configuration management."""

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application
    app_name: str = Field(default="claudeskills", description="Application name")
    app_version: str = Field(default="0.1.0", description="Application version")
    env: Literal["development", "staging", "production"] = Field(
        default="development", description="Environment"
    )
    debug: bool = Field(default=True, description="Debug mode")
    log_level: str = Field(default="INFO", description="Logging level")

    # API Configuration
    api_host: str = Field(default="0.0.0.0", description="API host")
    api_port: int = Field(default=8000, description="API port")
    api_workers: int = Field(default=4, description="Number of API workers")

    # Temporal Configuration
    temporal_host: str = Field(default="localhost", description="Temporal server host")
    temporal_port: int = Field(default=7233, description="Temporal server port")
    temporal_namespace: str = Field(default="default", description="Temporal namespace")
    temporal_task_queue: str = Field(
        default="claudeskills-tasks", description="Temporal task queue"
    )

    # Security
    secret_key: str = Field(
        default="your-secret-key-here-change-in-production",
        description="Secret key for JWT",
    )
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    jwt_expiration_minutes: int = Field(
        default=60, description="JWT token expiration in minutes"
    )

    # Rate Limiting
    rate_limit_per_minute: int = Field(
        default=60, description="Rate limit per minute per client"
    )

    # Monitoring
    enable_metrics: bool = Field(default=True, description="Enable Prometheus metrics")
    metrics_port: int = Field(default=9090, description="Metrics port")

    @property
    def temporal_address(self) -> str:
        """Get Temporal server address."""
        return f"{self.temporal_host}:{self.temporal_port}"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Global settings instance
settings = get_settings()
