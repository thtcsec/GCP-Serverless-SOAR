"""
Tests for GCP Threat Intel Service
"""

from unittest.mock import MagicMock, patch

from src.integrations.intel import ThreatIntelService


class TestThreatIntelService:
    @patch("src.integrations.intel.os.environ.get")
    def test_init_missing_keys(self, mock_env):
        mock_env.return_value = None
        service = ThreatIntelService()
        assert service.vt_api_key is None
        assert service.abuse_api_key is None

    @patch("src.integrations.intel.requests.get")
    def test_get_ip_report_success(self, mock_get):
        # Setup mocks for VT and AbuseIPDB
        mock_vt_response = MagicMock()
        mock_vt_response.status_code = 200
        mock_vt_response.json.return_value = {"data": {"attributes": {"last_analysis_stats": {"malicious": 5}}}}

        mock_abuse_response = MagicMock()
        mock_abuse_response.status_code = 200
        mock_abuse_response.json.return_value = {"data": {"abuseConfidenceScore": 80}}

        mock_get.side_effect = [mock_vt_response, mock_abuse_response]

        service = ThreatIntelService()
        service.vt_api_key = "dummy_vt"
        service.abuse_api_key = "dummy_abuse"

        report = service.get_ip_report("8.8.8.8")

        assert report["virustotal"]["malicious"] == 5
        assert report["abuseipdb"]["abuseConfidenceScore"] == 80

    @patch("src.integrations.intel.requests.get")
    def test_get_ip_report_http_error(self, mock_get):
        mock_get.side_effect = Exception("HTTP Error")

        service = ThreatIntelService()
        service.vt_api_key = "dummy_vt"
        service.abuse_api_key = "dummy_abuse"

        report = service.get_ip_report("1.2.3.4")

        # Fallback to local intelligence
        assert "virustotal" in report
        assert "abuseipdb" in report
