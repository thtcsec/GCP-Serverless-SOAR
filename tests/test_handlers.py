"""
Tests for GCP SOAR handlers module — unified incident pipeline.
"""

from unittest.mock import patch

from src.handlers import handle_event


class TestHandlers:
    """Test event handler functionality"""

    @patch("src.handlers.pipeline")
    def test_handle_event_success(self, mock_pipeline):
        mock_pipeline.process.return_value = {"statusCode": 200, "body": {"status": "executed"}}

        event = {"test": "event"}
        result = handle_event(event)

        assert result["statusCode"] == 200
        mock_pipeline.process.assert_called_once_with(event)

    @patch("src.handlers.pipeline")
    def test_handle_event_no_matching_playbook(self, mock_pipeline):
        mock_pipeline.process.return_value = {"statusCode": 200, "body": {"status": "no_playbook"}}

        event = {"test": "event"}
        result = handle_event(event)

        assert result["statusCode"] == 200
        assert result["body"]["status"] == "no_playbook"

    @patch("src.handlers.pipeline")
    def test_handle_event_playbook_failure(self, mock_pipeline):
        mock_pipeline.process.return_value = {"statusCode": 500, "body": {"status": "failed"}}

        event = {"test": "event"}
        result = handle_event(event)

        assert result["statusCode"] == 500

    @patch("src.handlers.pipeline")
    def test_handle_event_dry_run_preview(self, mock_pipeline):
        mock_pipeline.process.return_value = {
            "statusCode": 200,
            "body": {
                "mode": "dry_run",
                "playbook": "GCEContainment",
                "planned_actions": [],
            },
        }

        result = handle_event({"dry_run": True})

        assert result["statusCode"] == 200
        assert result["body"]["mode"] == "dry_run"
        assert result["body"]["playbook"] == "GCEContainment"

    @patch("src.handlers.pipeline")
    def test_handle_event_with_scc_finding(self, mock_pipeline):
        mock_pipeline.process.return_value = {"statusCode": 200, "body": {"status": "executed"}}

        event = {
            "name": "test-finding",
            "category": "Malware",
            "severity": "HIGH",
            "resourceName": "//compute.googleapis.com/projects/test/zones/us-central1-a/instances/test-vm",
            "state": "ACTIVE",
            "resource": {"name": "test", "projectDisplayName": "test", "type": "compute"},
        }

        result = handle_event(event)

        assert result["statusCode"] == 200
        mock_pipeline.process.assert_called_once()

    @patch("src.handlers.pipeline")
    def test_handle_event_with_iam_audit(self, mock_pipeline):
        mock_pipeline.process.return_value = {"statusCode": 200, "body": {"status": "executed"}}

        event = {
            "protoPayload": {
                "methodName": "CreateServiceAccountKey",
                "resourceName": "projects/test/serviceAccounts/test-sa@test.iam.gserviceaccount.com",
                "serviceName": "iam.googleapis.com",
                "authenticationInfo": {"principalEmail": "test@example.com"},
                "status": {},
                "request": {},
            },
            "timestamp": "2026-03-10T00:00:00Z",
            "resource": {"type": "service_account"},
        }

        result = handle_event(event)

        assert result["statusCode"] == 200
        mock_pipeline.process.assert_called_once()


class TestHandlerImports:
    """Test that all required modules can be imported"""

    def test_import_handlers(self):
        from src import handlers

        assert hasattr(handlers, "handle_event")
        assert hasattr(handlers, "pipeline")

    def test_import_playbook_registry(self):
        from src.playbooks.registry import PlaybookRegistry

        assert PlaybookRegistry is not None

    def test_import_all_playbooks(self):
        from src.playbooks.gce_containment import GCEContainment
        from src.playbooks.sa_compromise import SACompromise
        from src.playbooks.storage_exfiltration import StorageExfiltration

        assert GCEContainment is not None
        assert SACompromise is not None
        assert StorageExfiltration is not None
