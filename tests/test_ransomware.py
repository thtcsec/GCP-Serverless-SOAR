"""Tests for the Ransomware Response Playbook (GCP)."""

from unittest.mock import MagicMock, patch

import pytest

from src.playbooks.ransomware_response import RansomwareResponsePlaybook

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def mock_gcp_clients():
    """Prevent real GCP API calls during tests."""
    with (
        patch("src.playbooks.ransomware_response.gcp.get_instances_client") as mock_inst,
        patch("src.playbooks.ransomware_response.gcp.get_disks_client") as mock_disk,
        patch("src.playbooks.ransomware_response.gcp.get_storage_client") as mock_storage,
    ):
        yield {
            "instances": mock_inst,
            "disks": mock_disk,
            "storage": mock_storage,
        }


def _make_compute_finding(
    category: str = "Malware",
    severity: str = "HIGH",
    instance_name: str = "compromised-vm",
) -> dict:
    return {
        "name": "organizations/123/sources/456/findings/ransomware-001",
        "category": category,
        "severity": severity,
        "resourceName": f"//compute.googleapis.com/projects/test-proj/zones/us-central1-a/instances/{instance_name}",
        "state": "ACTIVE",
        "resource": {"name": "test", "projectDisplayName": "test-proj", "type": "compute"},
    }


def _make_storage_finding(bucket: str = "victim-bucket") -> dict:
    return {
        "name": "organizations/123/sources/456/findings/ransomware-storage-001",
        "category": "Ransomware",
        "severity": "CRITICAL",
        "resourceName": f"//storage.googleapis.com/buckets/{bucket}",
        "state": "ACTIVE",
        "resource": {"name": bucket, "projectDisplayName": "test-proj", "type": "storage"},
    }


# ---------------------------------------------------------------------------
# can_handle tests
# ---------------------------------------------------------------------------


class TestCanHandle:
    def test_matches_malware(self):
        pb = RansomwareResponsePlaybook()
        assert pb.can_handle(_make_compute_finding(category="Malware")) is True

    def test_matches_ransomware(self):
        pb = RansomwareResponsePlaybook()
        assert pb.can_handle(_make_storage_finding()) is True

    def test_matches_crypto_mining(self):
        pb = RansomwareResponsePlaybook()
        assert pb.can_handle(_make_compute_finding(category="Cryptocurrency mining")) is True

    def test_rejects_low_severity(self):
        pb = RansomwareResponsePlaybook()
        assert pb.can_handle(_make_compute_finding(severity="LOW")) is False

    def test_rejects_unrelated_category(self):
        pb = RansomwareResponsePlaybook()
        assert pb.can_handle(_make_compute_finding(category="Open Firewall")) is False

    def test_rejects_garbage(self):
        pb = RansomwareResponsePlaybook()
        assert pb.can_handle({"garbage": True}) is False


# ---------------------------------------------------------------------------
# execute tests — Compute Engine branch
# ---------------------------------------------------------------------------


class TestExecuteCompute:
    def test_full_compute_flow(self, mock_gcp_clients):
        """Snapshot → Isolate → Stop."""
        mock_instance_client = MagicMock()
        mock_gcp_clients["instances"].return_value = mock_instance_client

        # Mock instance with one disk
        mock_disk_obj = MagicMock()
        mock_disk_obj.source = "projects/test-proj/zones/us-central1-a/disks/boot-disk"
        mock_instance = MagicMock()
        mock_instance.disks = [mock_disk_obj]
        mock_instance.tags = MagicMock()
        mock_instance_client.get.return_value = mock_instance
        mock_instance_client.set_tags.return_value = MagicMock()

        mock_disk_client = MagicMock()
        mock_gcp_clients["disks"].return_value = mock_disk_client

        pb = RansomwareResponsePlaybook()
        result = pb.execute(_make_compute_finding())

        assert result is True
        mock_disk_client.create_snapshot.assert_called_once()
        mock_instance_client.stop.assert_called_once()


# ---------------------------------------------------------------------------
# execute tests — Cloud Storage branch
# ---------------------------------------------------------------------------


class TestExecuteStorage:
    def test_full_storage_flow(self, mock_gcp_clients):
        """Versioning → Remove public access."""
        mock_storage_client = MagicMock()
        mock_gcp_clients["storage"].return_value = mock_storage_client

        mock_bucket = MagicMock()
        mock_storage_client.get_bucket.return_value = mock_bucket

        # Simulate a public IAM binding
        mock_policy = MagicMock()
        mock_policy.bindings = [
            {"role": "roles/storage.objectViewer", "members": ["allUsers", "user:admin@corp.com"]},
        ]
        mock_bucket.get_iam_policy.return_value = mock_policy

        pb = RansomwareResponsePlaybook()
        result = pb.execute(_make_storage_finding())

        assert result is True
        mock_bucket.patch.assert_called_once()  # versioning
        mock_bucket.set_iam_policy.assert_called_once()  # removed allUsers


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_execute_failure_returns_false(self):
        """Simulate a hard failure."""
        with patch(
            "src.playbooks.ransomware_response.SCCFinding",
            side_effect=RuntimeError("boom"),
        ):
            pb = RansomwareResponsePlaybook()
            assert pb.execute(_make_compute_finding()) is False
