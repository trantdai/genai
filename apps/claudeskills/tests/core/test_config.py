"""Tests for configuration management."""

from claudeskills.core.config import Settings, get_settings


def test_settings_default_values() -> None:
    """Test that settings have correct default values."""
    settings = Settings()
    assert settings.app_name == "claudeskills"
    assert settings.app_version == "0.1.0"
    assert settings.env == "development"
    assert settings.temporal_host == "localhost"
    assert settings.temporal_port == 7233


def test_settings_temporal_address() -> None:
    """Test that temporal_address property works correctly."""
    settings = Settings()
    expected = f"{settings.temporal_host}:{settings.temporal_port}"
    assert settings.temporal_address == expected


def test_get_settings_returns_singleton() -> None:
    """Test that get_settings returns the same instance."""
    settings1 = get_settings()
    settings2 = get_settings()
    assert settings1 is settings2
