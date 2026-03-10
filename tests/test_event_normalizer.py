"""Tests for GCP Unified Event Normalizer."""
import pytest
from src.core.event_normalizer import EventNormalizer, UnifiedIncident


class TestUnifiedIncidentSchema:
    def test_default_platform_is_gcp(self):
        incident = UnifiedIncident()
        assert incident.platform == "gcp"

    def test_custom_fields(self):
        incident = UnifiedIncident(
            incident_id="test-456",
            severity="CRITICAL",
            source_ip="1.2.3.4",
            actor="admin@gcp.com",
        )
        assert incident.incident_id == "test-456"
        assert incident.severity == "CRITICAL"


class TestEventNormalizerSCC:
    @pytest.fixture
    def scc_finding(self):
        return {
            "name": "organizations/123/sources/456/findings/789",
            "category": "Cryptocurrency mining",
            "severity": "HIGH",
            "resourceName": "//compute.googleapis.com/projects/test/zones/us-central1-a/instances/test-vm",
            "state": "ACTIVE",
            "eventTime": "2026-03-10T00:00:00Z",
            "sourceProperties": {
                "sourceIp": "198.51.100.1",
                "principalEmail": "attacker@evil.com",
            },
        }

    def test_normalize_scc(self, scc_finding):
        result = EventNormalizer.normalize(scc_finding)
        assert result is not None
        assert result.platform == "gcp"
        assert result.source_ip == "198.51.100.1"
        assert result.severity == "HIGH"
        assert result.raw_event_type == "SCCFinding"
        assert result.resource_type == "compute_instance"

    def test_scc_correlation_keys(self, scc_finding):
        result = EventNormalizer.from_scc_finding(scc_finding)
        assert "198.51.100.1" in result.correlation_keys


class TestEventNormalizerIAMAudit:
    @pytest.fixture
    def iam_audit_event(self):
        return {
            "protoPayload": {
                "methodName": "CreateServiceAccountKey",
                "resourceName": "projects/test/serviceAccounts/sa@test.iam.gserviceaccount.com",
                "serviceName": "iam.googleapis.com",
                "authenticationInfo": {"principalEmail": "attacker@example.com"},
                "status": {},
                "request": {"callerIp": "203.0.113.5"},
            },
            "timestamp": "2026-03-10T00:00:00Z",
        }

    def test_normalize_iam_audit(self, iam_audit_event):
        result = EventNormalizer.normalize(iam_audit_event)
        assert result is not None
        assert result.platform == "gcp"
        assert result.actor == "attacker@example.com"
        assert result.action == "CreateServiceAccountKey"
        assert result.resource_type == "service_account"

    def test_iam_correlation_keys(self, iam_audit_event):
        result = EventNormalizer.from_iam_audit(iam_audit_event)
        assert "203.0.113.5" in result.correlation_keys
        assert "attacker@example.com" in result.correlation_keys


class TestEventNormalizerStorage:
    @pytest.fixture
    def storage_event(self):
        return {
            "protoPayload": {
                "methodName": "storage.objects.get",
                "resourceName": "projects/_/buckets/sensitive-bucket/objects/data.csv",
                "serviceName": "storage.googleapis.com",
                "authenticationInfo": {"principalEmail": "thief@corp.com"},
                "status": {},
                "request": {},
            },
            "timestamp": "2026-03-10T00:00:00Z",
        }

    def test_normalize_storage(self, storage_event):
        result = EventNormalizer.normalize(storage_event)
        assert result is not None
        assert result.resource == "sensitive-bucket"
        assert result.resource_type == "storage_bucket"

    def test_unknown_event_returns_none(self):
        result = EventNormalizer.normalize({"unknown": "data"})
        assert result is None
