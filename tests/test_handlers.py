"""
Tests for GCP SOAR handlers module
"""
import pytest
from unittest.mock import MagicMock, patch
from src.handlers import handle_event


class TestHandlers:
    """Test event handler functionality"""

    @patch('src.handlers.registry')
    def test_handle_event_success(self, mock_registry):
        """Test successful event handling"""
        mock_registry.dispatch.return_value = True
        
        event = {"test": "event"}
        result = handle_event(event)
        
        assert result["statusCode"] == 200
        assert "successfully" in result["body"]
        mock_registry.dispatch.assert_called_once_with(event)

    @patch('src.handlers.registry')
    def test_handle_event_no_matching_playbook(self, mock_registry):
        """Test event with no matching playbook"""
        mock_registry.dispatch.return_value = None
        
        event = {"test": "event"}
        result = handle_event(event)
        
        assert result["statusCode"] == 200
        assert "No matching playbook" in result["body"]

    @patch('src.handlers.registry')
    def test_handle_event_playbook_failure(self, mock_registry):
        """Test playbook execution failure"""
        mock_registry.dispatch.return_value = False
        
        event = {"test": "event"}
        result = handle_event(event)
        
        assert result["statusCode"] == 500
        assert "failed" in result["body"]

    @patch('src.handlers.registry')
    def test_handle_event_with_scc_finding(self, mock_registry):
        """Test handling SCC finding event"""
        mock_registry.dispatch.return_value = True
        
        event = {
            "name": "test-finding",
            "category": "Malware",
            "severity": "HIGH",
            "resourceName": "//compute.googleapis.com/projects/test/zones/us-central1-a/instances/test-vm",
            "state": "ACTIVE",
            "resource": {"name": "test", "projectDisplayName": "test", "type": "compute"}
        }
        
        result = handle_event(event)
        
        assert result["statusCode"] == 200
        mock_registry.dispatch.assert_called_once()

    @patch('src.handlers.registry')
    def test_handle_event_with_iam_audit(self, mock_registry):
        """Test handling IAM audit event"""
        mock_registry.dispatch.return_value = True
        
        event = {
            "protoPayload": {
                "methodName": "CreateServiceAccountKey",
                "resourceName": "projects/test/serviceAccounts/test-sa@test.iam.gserviceaccount.com",
                "serviceName": "iam.googleapis.com",
                "authenticationInfo": {"principalEmail": "test@example.com"},
                "status": {},
                "request": {}
            },
            "timestamp": "2026-03-10T00:00:00Z",
            "resource": {"type": "service_account"}
        }
        
        result = handle_event(event)
        
        assert result["statusCode"] == 200
        mock_registry.dispatch.assert_called_once()


class TestHandlerImports:
    """Test that all required modules can be imported"""

    def test_import_handlers(self):
        """Test handlers module imports"""
        from src import handlers
        assert hasattr(handlers, 'handle_event')

    def test_import_playbook_registry(self):
        """Test playbook registry imports"""
        from src.playbooks.registry import PlaybookRegistry
        assert PlaybookRegistry is not None

    def test_import_all_playbooks(self):
        """Test all playbooks can be imported"""
        from src.playbooks.gce_containment import GCEContainment
        from src.playbooks.sa_compromise import SACompromise
        from src.playbooks.storage_exfiltration import StorageExfiltration
        
        assert GCEContainment is not None
        assert SACompromise is not None
        assert StorageExfiltration is not None
