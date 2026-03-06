import pytest
import os
import sys
import json
from unittest.mock import patch, MagicMock

# Adding src to python path for testing
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))


# ==========================================
# Module Import Tests
# ==========================================

def test_import_main():
    from src import main

def test_import_sa_compromise():
    from src import sa_compromise_response

def test_import_storage_exfil():
    from src import storage_exfil_response

def test_import_handlers():
    from src import handlers

def test_import_queue_processor():
    from src import queue_processor

def test_import_core_modules():
    from src.core import config
    from src.core import logger

def test_import_models():
    from src.models import events

def test_import_clients():
    from src.clients import gcp

def test_import_playbooks():
    from src.playbooks import base
    from src.playbooks import registry
    from src.playbooks import gce_containment
    from src.playbooks import sa_compromise
    from src.playbooks import storage_exfiltration

def test_import_integrations():
    from src.integrations import slack_notifier
    from src.integrations import jira_manager
    from src.integrations import siem_forwarder

def test_import_cross_project():
    from src.cross_project import cross_project_responder

def test_import_workflow():
    from src.workflow import detect_severity
    from src.workflow import isolate_instance
    from src.workflow import create_snapshot
    from src.workflow import terminate_instance


# ==========================================
# Pydantic Model Tests
# ==========================================

class TestEventModels:
    def test_severity_enum(self):
        from src.models.events import Severity
        assert Severity.CRITICAL == "CRITICAL"
        assert Severity.HIGH == "HIGH"
        assert Severity.MEDIUM == "MEDIUM"
        assert Severity.LOW == "LOW"

    def test_finding_category_enum(self):
        from src.models.events import FindingCategory
        assert FindingCategory.CRYPTOCURRENCY == "Cryptocurrency mining"
        assert FindingCategory.MALWARE == "Malware"
        assert FindingCategory.DATA_EXFILTRATION == "Data Exfiltration"

    def test_scc_finding_model(self):
        from src.models.events import SCCFinding, SCCResource
        finding = SCCFinding(
            name="organizations/123/sources/456/findings/789",
            category="MALWARE",
            severity="HIGH",
            resource=SCCResource(
                name="//compute.googleapis.com/projects/test/zones/us-central1-a/instances/vm-1",
                type="google.compute.Instance",
                project_display_name="test",
            ),
            resourceName="//compute.googleapis.com/projects/test/zones/us-central1-a/instances/vm-1",
            eventTime="2024-01-01T00:00:00Z",
        )
        assert finding.category == "MALWARE"
        assert finding.resource.project_display_name == "test"

    def test_pubsub_message_model(self):
        from src.models.events import PubSubMessage
        msg = PubSubMessage(
            data="eyJ0ZXN0IjogdHJ1ZX0=",
            attributes={"type": "scc"},
            message_id="12345",
        )
        assert msg.message_id == "12345"


# ==========================================
# Core Config Tests
# ==========================================

class TestCoreConfig:
    def test_default_config(self):
        from src.core.config import SOARConfig
        cfg = SOARConfig()
        assert cfg.log_level == "INFO"
        assert cfg.region == "us-central1"

    @patch.dict(os.environ, {"LOG_LEVEL": "DEBUG", "GCP_REGION": "europe-west1"})
    def test_env_override_config(self):
        from src.core.config import SOARConfig
        cfg = SOARConfig()
        assert cfg.log_level == "DEBUG"
        assert cfg.region == "europe-west1"


# ==========================================
# Playbook Registry Tests
# ==========================================

class TestPlaybookRegistry:
    def test_register_and_dispatch(self):
        from src.playbooks.registry import PlaybookRegistry

        # Create a mock playbook class
        mock_playbook = MagicMock()
        mock_playbook.can_handle.return_value = True
        mock_playbook.execute.return_value = True

        registry = PlaybookRegistry()
        registry.register(mock_playbook)

        event = {"detail-type": "test"}
        result = registry.dispatch(event)

        mock_playbook.can_handle.assert_called_once_with(event)
        mock_playbook.execute.assert_called_once_with(event)
        assert result is True

    def test_dispatch_no_match(self):
        from src.playbooks.registry import PlaybookRegistry

        mock_playbook = MagicMock()
        mock_playbook.can_handle.return_value = False

        registry = PlaybookRegistry()
        registry.register(mock_playbook)

        result = registry.dispatch({"detail-type": "unknown"})
        assert result is None


# ==========================================
# GCE Containment Playbook Tests
# ==========================================

class TestGCEContainment:
    def _make_scc_event(self, instance_name="test-vm", zone="us-central1-a"):
        """Build an event dict that SCCFinding(**event) can parse."""
        return {
            "name": "organizations/123/sources/456/findings/789",
            "category": "Malware",
            "severity": "HIGH",
            "resourceName": f"//compute.googleapis.com/projects/test-project/zones/{zone}/instances/{instance_name}",
        }

    def test_can_handle_compute_finding(self):
        from src.playbooks.gce_containment import GCEContainment
        playbook = GCEContainment()
        event = self._make_scc_event()
        assert playbook.can_handle(event) is True

    def test_cannot_handle_non_compute_finding(self):
        from src.playbooks.gce_containment import GCEContainment
        playbook = GCEContainment()
        event = {
            "category": "DATA_EXFILTRATION",
            "resourceName": "//storage.googleapis.com/projects/test/buckets/my-bucket",
        }
        assert playbook.can_handle(event) is False

    @patch("src.playbooks.gce_containment.get_instances_client")
    @patch("src.playbooks.gce_containment.get_disks_client")
    @patch("src.playbooks.gce_containment.emit_metric")
    def test_execute_calls_isolation(self, mock_metric, mock_disks, mock_instances):
        from src.playbooks.gce_containment import GCEContainment

        # Mock instance get
        mock_instance = MagicMock()
        mock_instance.tags = MagicMock(items=["allow-ssh"], fingerprint="abc")
        mock_instance.disks = []
        mock_instance.service_accounts = [MagicMock(email="vm-sa@test.iam.gserviceaccount.com")]
        mock_instances.return_value.get.return_value = mock_instance

        # Mock operations to return completed operations
        mock_op = MagicMock()
        mock_op.result.return_value = None
        mock_instances.return_value.set_tags.return_value = mock_op
        mock_instances.return_value.set_service_account.return_value = mock_op
        mock_instances.return_value.set_metadata.return_value = mock_op
        mock_instances.return_value.stop.return_value = mock_op

        playbook = GCEContainment()
        event = self._make_scc_event()

        result = playbook.execute(event)
        assert result is True


# ==========================================
# SA Compromise Playbook Tests
# ==========================================

class TestSACompromise:
    def test_can_handle_iam_event(self):
        from src.playbooks.sa_compromise import SACompromise
        playbook = SACompromise()
        event = {
            "protoPayload": {
                "serviceName": "iam.googleapis.com",
                "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
            }
        }
        assert playbook.can_handle(event) is True

    def test_cannot_handle_compute_event(self):
        from src.playbooks.sa_compromise import SACompromise
        playbook = SACompromise()
        event = {
            "protoPayload": {
                "serviceName": "compute.googleapis.com",
                "methodName": "compute.instances.insert",
            }
        }
        assert playbook.can_handle(event) is False


# ==========================================
# Storage Exfiltration Playbook Tests
# ==========================================

class TestStorageExfiltration:
    def test_can_handle_storage_event(self):
        from src.playbooks.storage_exfiltration import StorageExfiltration
        playbook = StorageExfiltration()
        event = {
            "protoPayload": {
                "serviceName": "storage.googleapis.com",
                "methodName": "storage.objects.get",
            }
        }
        assert playbook.can_handle(event) is True


# ==========================================
# Logger Tests
# ==========================================

class TestLogger:
    def test_get_logger(self):
        from src.core.logger import get_logger
        log = get_logger("test_module")
        assert log.name == "test_module"


# ==========================================
# Workflow Function Tests
# ==========================================

class TestDetectSeverity:
    def test_classify_critical(self):
        from src.workflow.detect_severity import classify_severity
        result = classify_severity(9.0)
        assert result == "CRITICAL"

    def test_classify_low(self):
        from src.workflow.detect_severity import classify_severity
        result = classify_severity(2.0)
        assert result == "LOW"
