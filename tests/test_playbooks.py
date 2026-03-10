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

    @patch('src.playbooks.sa_compromise.SACompromise._notify_slack')
    @patch('src.playbooks.sa_compromise.SACompromise._send_alert')
    @patch('src.playbooks.sa_compromise.SACompromise._remove_critical_roles')
    @patch('src.playbooks.sa_compromise.SACompromise._disable_keys')
    @patch('src.integrations.scoring.ScoringEngine')
    @patch('src.integrations.intel.ThreatIntelService')
    @patch('src.playbooks.sa_compromise.emit_metric')
    @patch('src.playbooks.sa_compromise.PlaybookTimer')
    def test_execute_auto_isolate(self, mock_timer, mock_emit, mock_intel, mock_scoring, mock_disable, mock_remove, mock_alert, mock_slack, playbook, valid_iam_event):
        """Test successful execution resulting in AUTO_ISOLATE"""
        mock_timer.return_value.__enter__ = MagicMock()
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)
        
        # Mock high risk score
        mock_scoring_inst = mock_scoring.return_value
        mock_scoring_inst.calculate_risk_score.return_value = {"decision": "AUTO_ISOLATE", "risk_score": 90.0}
        
        result = playbook.execute(valid_iam_event)
        
        assert result is True
        assert mock_disable.called
        assert mock_remove.called
        assert mock_alert.called
        assert mock_slack.called

    @patch('src.playbooks.sa_compromise.SACompromise._notify_slack')
    @patch('src.playbooks.sa_compromise.SACompromise._send_alert')
    @patch('src.playbooks.sa_compromise.SACompromise._remove_critical_roles')
    @patch('src.playbooks.sa_compromise.SACompromise._disable_keys')
    @patch('src.integrations.scoring.ScoringEngine')
    @patch('src.integrations.intel.ThreatIntelService')
    @patch('src.playbooks.sa_compromise.PlaybookTimer')
    def test_execute_require_approval(self, mock_timer, mock_intel, mock_scoring, mock_disable, mock_remove, mock_alert, mock_slack, playbook, valid_iam_event):
        """Test successful execution resulting in REQUIRE_APPROVAL"""
        mock_timer.return_value.__enter__ = MagicMock()
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)
        
        # Mock medium risk score
        mock_scoring_inst = mock_scoring.return_value
        mock_scoring_inst.calculate_risk_score.return_value = {"decision": "REQUIRE_APPROVAL", "risk_score": 50.0}
        
        result = playbook.execute(valid_iam_event)
        
        assert result is True
        assert not mock_disable.called
        assert not mock_remove.called
        assert not mock_alert.called
        assert mock_slack.called

    @patch('src.playbooks.sa_compromise.SACompromise._notify_slack')
    @patch('src.playbooks.sa_compromise.SACompromise._send_alert')
    @patch('src.playbooks.sa_compromise.SACompromise._remove_critical_roles')
    @patch('src.playbooks.sa_compromise.SACompromise._disable_keys')
    @patch('src.integrations.scoring.ScoringEngine')
    @patch('src.integrations.intel.ThreatIntelService')
    @patch('src.playbooks.sa_compromise.PlaybookTimer')
    def test_execute_ignore(self, mock_timer, mock_intel, mock_scoring, mock_disable, mock_remove, mock_alert, mock_slack, playbook, valid_iam_event):
        """Test successful execution resulting in IGNORE"""
        mock_timer.return_value.__enter__ = MagicMock()
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)
        
        # Mock low risk score
        mock_scoring_inst = mock_scoring.return_value
        mock_scoring_inst.calculate_risk_score.return_value = {"decision": "IGNORE", "risk_score": 10.0}
        
        result = playbook.execute(valid_iam_event)
        
        assert result is True
        assert not mock_disable.called
        assert not mock_remove.called
        assert not mock_alert.called
        assert not mock_slack.called

    @patch('src.playbooks.sa_compromise.SACompromise._notify_slack')
    @patch('src.playbooks.sa_compromise.SACompromise._send_alert')
    @patch('src.playbooks.sa_compromise.SACompromise._remove_critical_roles')
    @patch('src.playbooks.sa_compromise.SACompromise._disable_keys')
    @patch('src.integrations.scoring.ScoringEngine')
    @patch('src.playbooks.sa_compromise.emit_metric')
    @patch('src.playbooks.sa_compromise.PlaybookTimer')
    def test_execute_internal_ip(self, mock_timer, mock_emit, mock_scoring, mock_disable, mock_remove, mock_alert, mock_slack, playbook, valid_iam_event):
        """Test successful execution resulting from internal IP local fallback calculation"""
        valid_iam_event["protoPayload"]["request"]["callerIp"] = "compute.google.com"

        mock_timer.return_value.__enter__ = MagicMock()
        mock_timer.return_value.__exit__ = MagicMock(return_value=False)
        
        # Mock medium internal risk score
        mock_scoring_inst = mock_scoring.return_value
        mock_scoring_inst.calculate_risk_score.return_value = {"decision": "REQUIRE_APPROVAL", "risk_score": 60.0}
        
        result = playbook.execute(valid_iam_event)
        
        assert result is True
        assert not mock_disable.called
        assert not mock_remove.called
        assert not mock_alert.called
        assert mock_slack.called


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
