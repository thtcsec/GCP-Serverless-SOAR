"""Unit tests for GCP Incident Report Generator."""

import os

import pytest

from src.core.report_generator import ReportGenerator


@pytest.fixture
def sample_incident():
    return {
        "incident_id": "abc123",
        "platform": "gcp",
        "severity": "CRITICAL",
        "source_ip": "198.51.100.10",
        "actor": "malicious-sa@project.iam.gserviceaccount.com",
        "action": "CRYPTO_MINING",
        "resource": "vm-abc123",
        "resource_type": "gce_instance",
        "risk_score": 85.0,
        "decision": "AUTO_ISOLATE",
        "anomaly_score": -0.8,
        "timestamp": "2026-03-11T12:00:00Z",
        "intel_summary": {
            "virustotal": {"malicious": 12},
            "abuseipdb": {"abuseConfidenceScore": 95},
        },
    }


class TestReportGenerator:
    def test_generate_creates_file(self, sample_incident, tmp_path):
        result = ReportGenerator.generate(sample_incident, output_dir=str(tmp_path))
        assert os.path.exists(result["report_path"])
        assert result["report_id"].startswith("IR-")

    def test_report_contains_key_fields(self, sample_incident, tmp_path):
        result = ReportGenerator.generate(sample_incident, output_dir=str(tmp_path))
        content = result["report_content"]
        assert "CRITICAL" in content
        assert "vm-abc123" in content
        assert "198.51.100.10" in content
        assert "85.0" in content
        assert "AUTO_ISOLATE" in content

    def test_report_with_custom_actions(self, sample_incident, tmp_path):
        actions = [
            {"action": "VM Isolated", "detail": "Firewall rules updated"},
            {"action": "Disk Snapshot", "detail": "snap-abc123"},
        ]
        result = ReportGenerator.generate(sample_incident, actions=actions, output_dir=str(tmp_path))
        assert "VM Isolated" in result["report_content"]
        assert "Disk Snapshot" in result["report_content"]

    def test_report_with_custom_recommendations(self, sample_incident, tmp_path):
        recs = ["Rotate all SA keys", "Review Audit Logs"]
        result = ReportGenerator.generate(sample_incident, recommendations=recs, output_dir=str(tmp_path))
        assert "Rotate all SA keys" in result["report_content"]

    def test_default_recommendations_critical(self):
        recs = ReportGenerator._default_recommendations("CRITICAL", "AUTO_ISOLATE")
        assert "Escalate" in recs
        assert "Verify isolation" in recs

    def test_report_with_empty_data(self, tmp_path):
        result = ReportGenerator.generate({}, output_dir=str(tmp_path))
        assert "UNKNOWN" in result["report_content"]
        assert os.path.exists(result["report_path"])
