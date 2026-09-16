"""Tests for the unified incident pipeline."""

from unittest.mock import MagicMock, patch

from src.core.pipeline import IncidentPipeline
from src.core.policy import PolicyEngine
from src.handlers import registry


class TestIncidentPipeline:
    @patch("src.core.pipeline.SlackNotifier")
    def test_pipeline_ignore_decision_skips_playbook(self, _mock_slack):
        pipeline = IncidentPipeline(registry=registry, policy=PolicyEngine())
        event = {
            "category": "Malware",
            "severity": "LOW",
            "resourceName": "//compute.googleapis.com/projects/p/zones/z/instances/i",
            "state": "ACTIVE",
            "resource": {"name": "i", "type": "compute.googleapis.com/Instance"},
        }

        with patch.object(registry, "dispatch") as mock_dispatch:
            result = pipeline.process(event)

        assert result["statusCode"] == 200
        assert result["body"]["decision"] == "IGNORE"
        mock_dispatch.assert_not_called()

    @patch("src.core.pipeline.SlackNotifier")
    def test_pipeline_auto_isolate_dispatches_playbook(self, _mock_slack):
        pipeline = IncidentPipeline(registry=registry, policy=PolicyEngine())
        event = {
            "category": "Malware",
            "severity": "CRITICAL",
            "resourceName": "//compute.googleapis.com/projects/p/zones/z/instances/i",
            "state": "ACTIVE",
            "indicator": {"ipAddresses": ["203.0.113.10"]},
            "resource": {"name": "i", "type": "compute.googleapis.com/Instance"},
        }

        def _auto_isolate(incident_obj):
            incident_obj.risk_score = 95.0
            incident_obj.decision = "AUTO_ISOLATE"
            return {
                "risk_score": 95.0,
                "decision": "AUTO_ISOLATE",
                "summary": "test",
                "decision_rationale": "test",
                "recommended_action": "isolate",
                "breakdown": {},
            }

        with (
            patch.object(PolicyEngine, "evaluate", side_effect=_auto_isolate),
            patch.object(registry, "dispatch", return_value=True) as mock_dispatch,
        ):
            result = pipeline.process(event)

        assert result["statusCode"] == 200
        mock_dispatch.assert_called_once()

    def test_pipeline_unknown_event_returns_422(self):
        pipeline = IncidentPipeline(registry=registry)
        result = pipeline.process({"unexpected": True})
        assert result["statusCode"] == 422

    @patch("src.core.pipeline.emit_metric")
    @patch("src.core.pipeline.SlackNotifier")
    def test_pipeline_enriches_response_with_mitre_ttps(self, _mock_slack, _mock_metric):
        classifier = MagicMock()
        classifier.predict_threat_severity.return_value = {
            "threat_type": "crypto_mining",
            "mitre_ttps": ["T1496"],
            "confidence": 0.9,
            "predicted_severity": "HIGH",
        }
        pipeline = IncidentPipeline(registry=registry, policy=PolicyEngine(), threat_classifier=classifier)
        event = {
            "category": "Malware",
            "severity": "LOW",
            "resourceName": "//compute.googleapis.com/projects/p/zones/z/instances/i",
            "state": "ACTIVE",
            "resource": {"name": "i", "type": "compute.googleapis.com/Instance"},
        }

        result = pipeline.process(event)

        assert result["statusCode"] == 200
        assert result["body"]["mitre_ttps"] == ["T1496"]
        assert result["body"]["threat_type"] == "crypto_mining"

    @patch("src.core.pipeline.emit_metric")
    @patch("src.core.pipeline.SlackNotifier")
    def test_pipeline_archives_audit_when_bucket_set(self, _mock_slack, _mock_metric, monkeypatch):
        audit = MagicMock()
        audit.log = MagicMock()
        audit.export_to_gcs = MagicMock(return_value=True)
        pipeline = IncidentPipeline(registry=registry, policy=PolicyEngine(), audit=audit)
        monkeypatch.setenv("AUDIT_GCS_BUCKET", "soar-audit-lab")

        event = {
            "category": "Malware",
            "severity": "LOW",
            "resourceName": "//compute.googleapis.com/projects/p/zones/z/instances/i",
            "state": "ACTIVE",
            "resource": {"name": "i", "type": "compute.googleapis.com/Instance"},
        }
        result = pipeline.process(event)

        assert result["statusCode"] == 200
        audit.export_to_gcs.assert_called_with("soar-audit-lab")
