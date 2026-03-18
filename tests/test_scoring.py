"""
Tests for GCP Scoring Engine
"""

from src.integrations.scoring import ScoringEngine


class TestScoringEngine:
    def test_calculate_risk_score_auto_isolate(self):
        engine = ScoringEngine()
        intel_data = {"virustotal": {"malicious": 15}, "abuseipdb": {"abuseConfidenceScore": 90}}
        initial_severity = 9.0

        # Raw score: (15 * 2) + (90 * 0.5) + (9.0 * 3) = 30 + 45 + 27 = 102 -> capped at 100
        result = engine.calculate_risk_score(intel_data, initial_severity)

        assert result["risk_score"] == 100.0
        assert result["decision"] == "AUTO_ISOLATE"
        assert result["breakdown"]["vt_malicious"] == 15
        assert result["breakdown"]["abuse_confidence"] == 90
        assert result["breakdown"]["initial_severity"] == 9.0

    def test_calculate_risk_score_require_approval(self):
        engine = ScoringEngine()
        intel_data = {"virustotal": {"malicious": 5}, "abuseipdb": {"abuseConfidenceScore": 40}}
        initial_severity = 5.0

        # Raw score: (5 * 2) + (40 * 0.5) + (5.0 * 3) = 10 + 20 + 15 = 45 -> REQUIRE_APPROVAL
        result = engine.calculate_risk_score(intel_data, initial_severity)

        assert result["risk_score"] == 45.0
        assert result["decision"] == "REQUIRE_APPROVAL"

    def test_calculate_risk_score_ignore(self):
        engine = ScoringEngine()
        intel_data = {"virustotal": {"malicious": 0}, "abuseipdb": {"abuseConfidenceScore": 10}}
        initial_severity = 2.0

        # Raw score: 0 + 5 + 6 = 11 -> IGNORE
        result = engine.calculate_risk_score(intel_data, initial_severity)

        assert result["risk_score"] == 11.0
        assert result["decision"] == "IGNORE"

    def test_calculate_risk_score_missing_data(self):
        engine = ScoringEngine()
        intel_data = {}
        initial_severity = 0.0

        result = engine.calculate_risk_score(intel_data, initial_severity)

        assert result["risk_score"] == 0.0
        assert result["decision"] == "IGNORE"
