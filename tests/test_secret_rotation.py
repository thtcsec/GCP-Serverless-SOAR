"""Tests for GCP Secret Rotation Manager."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from src.core.secret_rotation import SecretRotationManager


class TestSecretRotationManager:
    @pytest.fixture
    def secret_client(self):
        return MagicMock()

    @pytest.fixture
    def manager(self, secret_client):
        return SecretRotationManager(secret_client=secret_client)

    def test_check_key_age_fresh(self, manager, secret_client):
        secret_client.get_secret.return_value = MagicMock(create_time=datetime.now(UTC) - timedelta(days=10))
        secret_client.access_secret_version.return_value = MagicMock()
        result = manager.check_key_age("my-project", "virustotal-api-key")
        assert result["age_days"] == 10
        assert result["needs_rotation"] is False

    def test_check_key_age_stale(self, manager, secret_client):
        secret_client.get_secret.return_value = MagicMock(create_time=datetime.now(UTC) - timedelta(days=100))
        secret_client.access_secret_version.return_value = MagicMock()
        result = manager.check_key_age("my-project", "virustotal-api-key")
        assert result["age_days"] == 100
        assert result["needs_rotation"] is True

    def test_rotate_secret(self, manager, secret_client):
        result = manager.rotate_secret("my-project", "virustotal-api-key", "new-key")
        assert result is True
        secret_client.add_secret_version.assert_called_once()

    def test_rotate_secret_failure(self, manager, secret_client):
        secret_client.add_secret_version.side_effect = Exception("Permission denied")
        result = manager.rotate_secret("my-project", "test", "value")
        assert result is False

    def test_get_rotation_report(self, manager, secret_client):
        secret_client.get_secret.return_value = MagicMock(create_time=datetime.now(UTC) - timedelta(days=50))
        secret_client.access_secret_version.return_value = MagicMock()
        report = manager.get_rotation_report("my-project", ["key1", "key2"])
        assert report["total_secrets"] == 2
        assert report["needs_rotation"] == 0

    def test_no_client_returns_error(self):
        manager = SecretRotationManager()
        result = manager.check_key_age("proj", "test")
        assert "error" in result

    def test_get_monitored_secrets(self):
        secrets = SecretRotationManager.get_monitored_secrets()
        assert len(secrets) == 5
        assert "virustotal-api-key" in secrets
