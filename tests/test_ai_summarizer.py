"""Unit tests for GCP AI Summarizer (Vertex AI)."""

from unittest.mock import MagicMock, patch
import pytest
from src.integrations.ai_summarizer import AISummarizer


@pytest.fixture
def mock_vertex_model():
    """Create a mock Vertex AI GenerativeModel."""
    model = MagicMock()
    response = MagicMock()
    response.text = "A crypto miner was detected on instance vm-abc123. Severity is CRITICAL. Recommend immediate VM isolation and disk snapshot for forensics."
    model.generate_content.return_value = response
    return model


@pytest.fixture
def sample_incident():
    return {
        "incident_id": "abc123",
        "platform": "gcp",
        "severity": "CRITICAL",
        "source_ip": "198.51.100.10",
        "actor": "unknown",
        "action": "CRYPTO_MINING",
        "resource": "vm-abc123",
        "resource_type": "gce_instance",
        "risk_score": 85.0,
        "decision": "AUTO_ISOLATE",
    }


class TestAISummarizer:
    def test_summarize_success(self, mock_vertex_model, sample_incident):
        summarizer = AISummarizer(client=mock_vertex_model)
        result = summarizer.summarize_incident(sample_incident)

        assert "crypto miner" in result["summary"].lower()
        assert result["model_name"] == "gemini-3-flash-preview"
        mock_vertex_model.generate_content.assert_called_once()

    def test_summarize_fallback_on_error(self, sample_incident):
        model = MagicMock()
        model.generate_content.side_effect = Exception("Service unavailable")

        summarizer = AISummarizer(client=model)
        result = summarizer.summarize_incident(sample_incident)

        assert result["model_name"] == "fallback"
        assert "[AUTO]" in result["summary"]
        assert "vm-abc123" in result["summary"]

    def test_fallback_summary_content(self, sample_incident):
        result = AISummarizer._fallback_summary(sample_incident)

        assert result["model_name"] == "fallback"
        assert "CRITICAL" in result["summary"]
        assert "vm-abc123" in result["summary"]
        assert "AUTO_ISOLATE" in result["summary"]
        assert "85.0" in result["summary"]

    def test_fallback_with_empty_data(self):
        result = AISummarizer._fallback_summary({})

        assert result["model_name"] == "fallback"
        assert "UNKNOWN" in result["summary"]
