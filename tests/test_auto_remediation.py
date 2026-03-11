"""Unit tests for GCP Auto-Remediation Patching."""

from unittest.mock import MagicMock
import pytest
from src.core.auto_remediation import AutoRemediation


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.set_metadata.return_value = None
    return client


@pytest.fixture
def remediation(mock_client):
    return AutoRemediation(client=mock_client, project_id="test-project", zone="us-central1-a")


class TestAutoRemediation:
    def test_patch_matching_packages(self, remediation, mock_client):
        result = remediation.patch_instance("vm-abc123", ["openssl vulnerability", "curl exploit"])
        assert result["status"] == "sent"
        assert "openssl" in result["packages_patched"]
        mock_client.set_metadata.assert_called_once()

    def test_patch_no_matching_packages(self, remediation):
        result = remediation.patch_instance("vm-abc123", ["unknown-vuln"])
        assert result["status"] == "skipped"
        assert "No matching packages" in result["reason"]

    def test_patch_deduplication(self, remediation, mock_client):
        result = remediation.patch_instance("vm-abc123", ["openssl", "OpenSSL CVE"])
        assert result["status"] == "sent"
        assert len(result["packages_patched"]) == len(set(result["packages_patched"]))

    def test_patch_gce_error(self):
        client = MagicMock()
        client.set_metadata.side_effect = Exception("Instance not found")
        remediation = AutoRemediation(client=client, project_id="test", zone="us-central1-a")
        result = remediation.patch_instance("vm-bad", ["openssl"])
        assert result["status"] == "error"
        assert "vm-bad" in result["instance_name"]
