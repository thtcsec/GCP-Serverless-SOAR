"""
Comprehensive tests for GCP SOAR playbooks
"""
import pytest
from unittest.mock import MagicMock, patch, call
from src.playbooks.gce_containment import GCEContainment
from src.playbooks.sa_compromise import SACompromise
from src.playbooks.storage_exfiltration import StorageExfiltration
from src.models.events import SCCFinding, IAMAuditEvent, StorageAuditEvent


class TestGCEContainmentPlaybook:
    """Test GCE Containment Playbook"""

    @pytest.fixture
    def playbook(self):
        return GCEContainment()

    @pytest.fixture
    def valid_scc_finding(self):
        return {
            "name": "organizations/123/sources/456/findings/789",
            "category": "Cryptocurrency mining",
            "severity": "HIGH",
            "resourceName": "//compute.googleapis.com/projects/test-project/zones/us-central1-a/instances/test-instance",
            "state": "ACTIVE",
            "eventTime": "2026-03-10T00:00:00Z",
            "createTime": "2026-03-10T00:00:00Z",
            "sourceProperties": {},
            "resource": {
                "name": "test-instance",
                "projectDisplayName": "Test Project",
                "type": "compute.googleapis.com/Instance"
            }
        }

    def test_can_handle_high_severity_compute(self, playbook, valid_scc_finding):
        """Test playbook handles HIGH severity compute findings"""
        assert playbook.can_handle(valid_scc_finding) is True

    def test_can_handle_critical_severity(self, playbook, valid_scc_finding):
        """Test playbook handles CRITICAL severity"""
        valid_scc_finding["severity"] = "CRITICAL"
        assert playbook.can_handle(valid_scc_finding) is True

    def test_cannot_handle_low_severity(self, playbook, valid_scc_finding):
        """Test playbook rejects LOW severity"""
        valid_scc_finding["severity"] = "LOW"
        assert playbook.can_handle(valid_scc_finding) is False

    def test_cannot_handle_non_compute_resource(self, playbook, valid_scc_finding):
        """Test playbook rejects non-compute resources"""
        valid_scc_finding["resourceName"] = "//storage.googleapis.com/projects/test/buckets/test-bucket"
        assert playbook.can_handle(valid_scc_finding) is False

    def test_cannot_handle_malformed_event(self, playbook):
        """Test playbook rejects malformed events"""
        assert playbook.can_handle({"invalid": "data"}) is False

    @patch('src.playbooks.gce_containment.get_instances_client')
    @patch('src.playbooks.gce_containment.get_disks_client')
    def test_execute_success(self, mock_get_disks, mock_get_instances, playbook, valid_scc_finding):
        """Test successful playbook execution"""
        # Set up mocks
        mock_instances = MagicMock()
        mock_get_instances.return_value = mock_instances
        mock_disks = MagicMock()
        mock_get_disks.return_value = mock_disks

        # Mock instance response
        mock_instance = MagicMock()
        mock_instance.tags.items = []
        mock_instance.disks = [MagicMock(boot=True, source="projects/test/zones/us-central1-a/disks/test-disk")]
        mock_instances.get.return_value = mock_instance
        
        # Mock operations
        mock_operation = MagicMock()
        mock_operation.result.return_value = None
        mock_instances.set_tags.return_value = mock_operation
        mock_instances.set_service_account.return_value = mock_operation
        mock_instances.set_metadata.return_value = mock_operation
        mock_instances.stop.return_value = mock_operation
        mock_disks.create_snapshot.return_value = mock_operation

        result = playbook.execute(valid_scc_finding)
        
        assert result is True
        assert mock_instances.set_tags.called
        assert mock_instances.stop.called


class TestSACompromisePlaybook:
    """Test Service Account Compromise Playbook"""

    @pytest.fixture
    def playbook(self):
        return SACompromise()

    @pytest.fixture
    def valid_iam_event(self):
        return {
            "protoPayload": {
                "methodName": "CreateServiceAccountKey",
                "resourceName": "projects/test-project/serviceAccounts/test-sa@test-project.iam.gserviceaccount.com",
                "serviceName": "iam.googleapis.com",
                "authenticationInfo": {
                    "principalEmail": "attacker@example.com"
                },
                "status": {},
                "request": {}
            },
            "timestamp": "2026-03-10T00:00:00Z",
            "resource": {
                "type": "service_account",
                "labels": {}
            }
        }

    def test_can_handle_risky_iam_action(self, playbook, valid_iam_event):
        """Test playbook handles risky IAM actions"""
        assert playbook.can_handle(valid_iam_event) is True

    def test_can_handle_set_iam_policy(self, playbook, valid_iam_event):
        """Test playbook handles SetIamPolicy"""
        valid_iam_event["protoPayload"]["methodName"] = "SetIamPolicy"
        assert playbook.can_handle(valid_iam_event) is True

    def test_cannot_handle_safe_action(self, playbook, valid_iam_event):
        """Test playbook rejects safe IAM actions"""
        valid_iam_event["protoPayload"]["methodName"] = "GetServiceAccount"
        assert playbook.can_handle(valid_iam_event) is False

    def test_cannot_handle_malformed_event(self, playbook):
        """Test playbook rejects malformed events"""
        assert playbook.can_handle({"invalid": "data"}) is False


class TestStorageExfiltrationPlaybook:
    """Test Storage Exfiltration Playbook"""

    @pytest.fixture
    def playbook(self):
        return StorageExfiltration()

    @pytest.fixture
    def valid_storage_event(self):
        return {
            "protoPayload": {
                "methodName": "storage.objects.get",
                "resourceName": "projects/_/buckets/test-bucket/objects/sensitive-data.txt",
                "serviceName": "storage.googleapis.com",
                "authenticationInfo": {
                    "principalEmail": "attacker@example.com"
                },
                "status": {},
                "request": {}
            },
            "timestamp": "2026-03-10T00:00:00Z"
        }

    def test_can_handle_get_object(self, playbook, valid_storage_event):
        """Test playbook handles storage.objects.get"""
        assert playbook.can_handle(valid_storage_event) is True

    def test_can_handle_list_objects(self, playbook, valid_storage_event):
        """Test playbook handles storage.objects.list"""
        valid_storage_event["protoPayload"]["methodName"] = "storage.objects.list"
        assert playbook.can_handle(valid_storage_event) is True

    def test_cannot_handle_write_operation(self, playbook, valid_storage_event):
        """Test playbook rejects write operations"""
        valid_storage_event["protoPayload"]["methodName"] = "storage.objects.create"
        assert playbook.can_handle(valid_storage_event) is False

    def test_cannot_handle_malformed_event(self, playbook):
        """Test playbook rejects malformed events"""
        assert playbook.can_handle({"invalid": "data"}) is False


class TestPlaybookIntegration:
    """Integration tests for playbook registry"""

    @patch('src.playbooks.gce_containment.get_instances_client')
    @patch('src.playbooks.gce_containment.get_disks_client')
    def test_registry_dispatches_to_correct_playbook(self, mock_get_disks, mock_get_instances):
        """Test registry dispatches events to correct playbook"""
        from src.playbooks.registry import PlaybookRegistry
        
        registry = PlaybookRegistry()
        registry.register(GCEContainment())
        registry.register(SACompromise())
        registry.register(StorageExfiltration())

        mock_instances = MagicMock()
        mock_get_instances.return_value = mock_instances
        
        # Mock compute client
        mock_instance = MagicMock()
        mock_instance.tags.items = []
        mock_instance.disks = []
        mock_instances.get.return_value = mock_instance
        
        mock_operation = MagicMock()
        mock_operation.result.return_value = None
        mock_instances.set_tags.return_value = mock_operation
        mock_instances.set_service_account.return_value = mock_operation
        mock_instances.set_metadata.return_value = mock_operation
        mock_instances.stop.return_value = mock_operation

        # Test GCE event
        gce_event = {
            "name": "test-finding",
            "category": "Malware",
            "severity": "HIGH",
            "resourceName": "//compute.googleapis.com/projects/test/zones/us-central1-a/instances/test-vm",
            "state": "ACTIVE",
            "resource": {"name": "test", "projectDisplayName": "test", "type": "compute"}
        }
        
        result = registry.dispatch(gce_event)
        assert result is True

    def test_registry_returns_none_for_unhandled_event(self):
        """Test registry returns None for unhandled events"""
        from src.playbooks.registry import PlaybookRegistry
        
        registry = PlaybookRegistry()
        registry.register(GCEContainment())

        unhandled_event = {"unknown": "event"}
        result = registry.dispatch(unhandled_event)
        assert result is None
