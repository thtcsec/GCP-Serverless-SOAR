import os
from unittest.mock import MagicMock, patch

os.environ["PROJECT_ID"] = "test-project"
os.environ["ALERT_TOPIC"] = "test-topic"

import src.sa_compromise_response as resp


def make_cloud_event(
    method_name="iam.serviceAccounts.createKey",
    sa_email="test@project.iam.gserviceaccount.com",
    caller_ip="1.2.3.4",
):
    return MagicMock(
        data={
            "protoPayload": {
                "methodName": method_name,
                "resourceName": f"projects/test-project/serviceAccounts/{sa_email}" if sa_email else "",
                "authenticationInfo": {"principalEmail": "attacker@example.com"},
                "request": {"callerIp": caller_ip},
            }
        }
    )


class TestSACompromiseResponse:
    @patch("src.sa_compromise_response.setup_logging")
    @patch("src.sa_compromise_response.integrations.ScoringEngine")
    @patch("src.sa_compromise_response.integrations.ThreatIntelService")
    @patch("src.sa_compromise_response.execute_sa_response")
    def test_sa_compromise_responder(self, mock_exec, mock_intel, mock_scoring, mock_setup):
        mock_intel.return_value.get_ip_report.return_value = {}
        mock_scoring.return_value.calculate_risk_score.return_value = {
            "decision": "AUTO_ISOLATE",
            "risk_score": 90,
        }

        event = make_cloud_event()
        resp.sa_compromise_responder(event)
        mock_exec.assert_called_once()

    @patch("src.sa_compromise_response.integrations.ScoringEngine")
    @patch("src.sa_compromise_response.integrations.ThreatIntelService")
    def test_process_sa_event_low_risk(self, mock_intel, mock_scoring):
        mock_intel.return_value.get_ip_report.return_value = {}
        mock_scoring.return_value.calculate_risk_score.return_value = {
            "decision": "IGNORE",
            "risk_score": 1,
        }

        payload = make_cloud_event().data["protoPayload"]
        with patch("src.sa_compromise_response.execute_sa_response") as mock_exec:
            resp.process_sa_event(payload)
            mock_exec.assert_not_called()

    @patch("src.sa_compromise_response.integrations.ScoringEngine")
    @patch("src.sa_compromise_response.integrations.ThreatIntelService")
    def test_process_sa_event_high_risk(self, mock_intel, mock_scoring):
        mock_intel.return_value.get_ip_report.return_value = {}
        mock_scoring.return_value.calculate_risk_score.return_value = {
            "decision": "AUTO_ISOLATE",
            "risk_score": 95,
        }

        payload = make_cloud_event().data["protoPayload"]
        with patch("src.sa_compromise_response.execute_sa_response") as mock_exec:
            resp.process_sa_event(payload)
            mock_exec.assert_called_once()

    def test_extract_sa_email(self):
        assert resp.extract_sa_email("projects/p/serviceAccounts/test@p.iam") == "test@p.iam"
        assert resp.extract_sa_email("projects/p/instances/i1") is None

    @patch("src.sa_compromise_response.get_iam_client")
    @patch("src.sa_compromise_response.iam_admin_v1")
    def test_disable_sa_keys(self, mock_v1, mock_get_iam):
        mock_client = MagicMock()
        mock_get_iam.return_value = mock_client
        mock_key = MagicMock()
        mock_key.key_type = "USER_MANAGED"
        mock_v1.ServiceAccountKey.Type.USER_MANAGED = "USER_MANAGED"
        mock_key.name = "key1"
        mock_client.list_service_account_keys.return_value.keys = [mock_key]

        resp.disable_sa_keys("test_sa")
        mock_client.disable_service_account_key.assert_called_once_with(name="key1")

    @patch("src.sa_compromise_response.get_publisher")
    def test_send_sa_alert(self, mock_pub):
        mock_pub.return_value.publish.return_value.result.return_value = "msg-id"
        resp.send_sa_alert("sa", "pr", {"risk_score": 90}, {})
        mock_pub.return_value.publish.assert_called_once()
