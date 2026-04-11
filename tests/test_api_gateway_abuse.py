from unittest.mock import MagicMock, patch

import pytest

from src.playbooks.api_gateway_abuse import APIGatewayAbusePlaybook


@pytest.fixture(autouse=True)
def mock_gcp_client():
    with patch("src.playbooks.api_gateway_abuse.gcp.get_security_policies_client") as mock:
        yield mock


@pytest.fixture
def gcp_abuse_event():
    return {
        "protoPayload": {
            "serviceName": "apigateway.googleapis.com",
            "methodName": "something",
            "request": {"callerIp": "203.0.113.5"},
            "status": {"code": 429},
        }
    }


def test_can_handle_abuse(gcp_abuse_event):
    playbook = APIGatewayAbusePlaybook()
    assert playbook.can_handle(gcp_abuse_event) is True


def test_can_handle_invalid_source(gcp_abuse_event):
    playbook = APIGatewayAbusePlaybook()
    gcp_abuse_event["protoPayload"]["serviceName"] = "storage.googleapis.com"
    assert playbook.can_handle(gcp_abuse_event) is False


def test_can_handle_invalid_event():
    playbook = APIGatewayAbusePlaybook()
    assert playbook.can_handle({"invalid": "data"}) is False


@patch.dict("os.environ", {"CLOUD_ARMOR_POLICY_NAME": "test-policy", "GOOGLE_CLOUD_PROJECT": "test-project"})
def test_execute_success(mock_gcp_client, gcp_abuse_event):
    mock_client = MagicMock()
    mock_gcp_client.return_value = mock_client

    mock_policy = MagicMock()
    # Mock empty rules to force addition
    mock_policy.rules = []
    mock_client.get.return_value = mock_policy

    playbook = APIGatewayAbusePlaybook()
    result = playbook.execute(gcp_abuse_event)

    assert result is True
    mock_client.get.assert_called_once_with(project="test-project", security_policy="test-policy")
    mock_client.add_rule.assert_called_once()


@patch.dict("os.environ", {"CLOUD_ARMOR_POLICY_NAME": "", "GOOGLE_CLOUD_PROJECT": ""})
def test_execute_no_config(gcp_abuse_event):
    playbook = APIGatewayAbusePlaybook()
    result = playbook.execute(gcp_abuse_event)
    assert result is False
