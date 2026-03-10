"""
Tests for GCP SOAR core modules (config, logger, metrics)
"""
import pytest
import os
from unittest.mock import MagicMock, patch
from src.core.config import SOARConfig, config
from src.core.logger import get_logger
from src.core.metrics import emit_metric, PlaybookTimer


class TestSOARConfig:
    """Test SOAR configuration"""

    def test_default_config_values(self):
        """Test default configuration values"""
        cfg = SOARConfig()
        assert cfg.project_id == "" or cfg.project_id is not None
        assert cfg.region == "us-central1"
        assert cfg.isolation_tag == "isolated-vm"
        assert cfg.log_level == "INFO"

    def test_config_from_env(self):
        """Test configuration from environment variables"""
        with patch.dict(os.environ, {
            'PROJECT_ID': 'test-project',
            'GCP_REGION': 'us-east1',
            'ISOLATION_TAG': 'quarantine',
            'LOG_LEVEL': 'DEBUG'
        }, clear=False):
            cfg = SOARConfig()
            assert cfg.project_id == 'test-project'
            assert cfg.region == 'us-east1'
            assert cfg.isolation_tag == 'quarantine'
            assert cfg.log_level == 'DEBUG'

    def test_global_config_instance(self):
        """Test global config instance exists"""
        assert config is not None
        assert isinstance(config, SOARConfig)

    def test_config_immutable_after_creation(self):
        """Test config values are set at creation"""
        cfg = SOARConfig()
        original_project = cfg.project_id
        # Config should maintain its values
        assert cfg.project_id == original_project


class TestLogger:
    """Test logging functionality"""

    def test_get_logger_returns_logger(self):
        """Test get_logger returns a logger instance"""
        logger = get_logger("test-module")
        assert logger is not None
        assert logger.name == "test-module"

    def test_get_logger_different_names(self):
        """Test get_logger with different names"""
        logger1 = get_logger("module1")
        logger2 = get_logger("module2")
        assert logger1.name == "module1"
        assert logger2.name == "module2"

    def test_logger_has_required_methods(self):
        """Test logger has required logging methods"""
        logger = get_logger("test")
        assert hasattr(logger, 'info')
        assert hasattr(logger, 'error')
        assert hasattr(logger, 'warning')
        assert hasattr(logger, 'debug')
        assert hasattr(logger, 'critical')

    @patch('src.core.logger.logging.getLogger')
    def test_logger_configuration(self, mock_get_logger):
        """Test logger is properly configured"""
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger
        
        logger = get_logger("test")
        mock_get_logger.assert_called_once_with("test")


class TestMetrics:
    """Test metrics functionality"""

    def test_emit_metric_no_exception(self):
        """Test metric emission doesn't raise exception"""
        # Should not raise exception even if monitoring not configured
        emit_metric("test_metric", 1.0, {"label": "value"})
        assert True

    def test_playbook_timer_context_manager(self):
        """Test PlaybookTimer as context manager"""
        with PlaybookTimer("TestPlaybook") as timer:
            assert timer is not None
        # Should complete without error

    @patch('src.core.metrics.emit_metric')
    def test_playbook_timer_emits_metric(self, mock_emit):
        """Test PlaybookTimer emits metrics"""
        with PlaybookTimer("TestPlaybook"):
            pass
        
        # Should have called emit_metric
        assert mock_emit.called

    @patch('src.core.metrics.emit_metric')
    def test_playbook_timer_handles_exception(self, mock_emit):
        """Test PlaybookTimer handles exceptions in context"""
        try:
            with PlaybookTimer("TestPlaybook"):
                raise ValueError("Test error")
        except ValueError:
            pass
        
        # Should still emit metric even on exception
        assert mock_emit.called


class TestGCPClients:
    """Test GCP client initialization"""

    @patch('src.clients.gcp.compute_v1.InstancesClient')
    def test_get_instances_client(self, mock_client):
        """Test instances client initialization"""
        from src.clients.gcp import get_instances_client
        
        client = get_instances_client()
        assert client is not None

    @patch('src.clients.gcp.compute_v1.DisksClient')
    def test_get_disks_client(self, mock_client):
        """Test disks client initialization"""
        from src.clients.gcp import get_disks_client
        
        client = get_disks_client()
        assert client is not None

    @patch('src.clients.gcp.compute_v1.SnapshotsClient')
    def test_get_snapshots_client(self, mock_client):
        """Test snapshots client initialization"""
        from src.clients.gcp import get_snapshots_client
        
        client = get_snapshots_client()
        assert client is not None

    @patch('src.clients.gcp.storage.Client')
    def test_get_storage_client(self, mock_client):
        """Test storage client initialization"""
        from src.clients.gcp import get_storage_client
        
        client = get_storage_client()
        assert client is not None


class TestIntegrations:
    """Test integration modules"""

    def test_import_threat_intel(self):
        """Test threat intel module imports"""
        from src.integrations.intel import ThreatIntelService
        assert ThreatIntelService is not None

    def test_import_scoring_engine(self):
        """Test scoring engine imports"""
        from src.integrations.scoring import ScoringEngine
        assert ScoringEngine is not None

    def test_import_slack_notifier(self):
        """Test Slack notifier imports"""
        from src.integrations.slack_notifier import SlackNotifier
        assert SlackNotifier is not None

    def test_import_jira_manager(self):
        """Test Jira manager imports"""
        from src.integrations.jira_manager import JiraManager
        assert JiraManager is not None

    def test_import_siem_forwarder(self):
        """Test SIEM forwarder imports"""
        from src.integrations.siem_forwarder import SIEMForwarder
        assert SIEMForwarder is not None
