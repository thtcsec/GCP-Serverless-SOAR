import os
import json
import pytest
from unittest.mock import patch, MagicMock

os.environ['PROJECT_ID'] = 'test-project'
os.environ['ALERT_TOPIC'] = 'test-topic'

import src.sa_compromise_response as resp

if 'PROJECT_ID' in os.environ:
    del os.environ['PROJECT_ID']
if 'ALERT_TOPIC' in os.environ:
    del os.environ['ALERT_TOPIC']

def make_cloud_event(method_name='iam.serviceAccounts.createKey', 
                     sa_email='test@project.iam.gserviceaccount.com',
                     caller_ip='1.2.3.4'):
    return MagicMock(data={
        'protoPayload': {
            'methodName': method_name,
            'resourceName': f'projects/test-project/serviceAccounts/{sa_email}' if sa_email else '',
            'authenticationInfo': {'principalEmail': 'attacker@example.com'},
            'request': {'callerIp': caller_ip}
        }
    })

class TestSACompromiseResponse:

    @patch('src.sa_compromise_response.setup_logging')
    @patch('src.sa_compromise_response.process_sa_event')
    def test_sa_compromise_responder(self, mock_process, mock_setup):
        event = make_cloud_event()
        resp.sa_compromise_responder(event)
        mock_process.assert_called_once()
        
    @patch('src.sa_compromise_response.process_sa_event', side_effect=Exception('Test Error'))
    def test_sa_compromise_responder_error(self, mock_process):
        # Should not raise
        resp.sa_compromise_responder(make_cloud_event())

    @patch('src.sa_compromise_response.execute_sa_response')
    def test_process_sa_event(self, mock_exec):
        payload = make_cloud_event().data['protoPayload']
        
        # Test low risk
        with patch('src.sa_compromise_response.calculate_sa_risk_score', return_value=3):
            resp.process_sa_event(payload)
            mock_exec.assert_not_called()
            
        # Test high risk
        with patch('src.sa_compromise_response.calculate_sa_risk_score', return_value=10):
            resp.process_sa_event(payload)
            mock_exec.assert_called_once()
            
        # Test non matching method
        payload_non_match = make_cloud_event('compute.instances.insert').data['protoPayload']
        resp.process_sa_event(payload_non_match)
        
        # Test empty SA email
        payload_no_email = make_cloud_event('iam.serviceAccounts.keys.create', sa_email=None).data['protoPayload']
        resp.process_sa_event(payload_no_email)

    def test_extract_sa_email(self):
        assert resp.extract_sa_email('projects/p/serviceAccounts/test@p.iam') == 'test@p.iam'
        assert resp.extract_sa_email('projects/p/instances/i1') is None

    @patch('src.sa_compromise_response.is_suspicious_timing')
    @patch('src.sa_compromise_response.is_unusual_source')
    def test_calculate_sa_risk_score(self, mock_ip, mock_timing):
        mock_ip.return_value = True # +3
        mock_timing.return_value = True # +2
        
        payload = make_cloud_event('CreateServiceAccountKey').data['protoPayload'] # +5
        assert resp.calculate_sa_risk_score(payload) == 10
        
        mock_timing.return_value = False
        payload2 = make_cloud_event('OtherMethod').data['protoPayload']
        assert resp.calculate_sa_risk_score(payload2) == 3

    def test_is_unusual_source(self):
        payload1 = make_cloud_event(caller_ip='1.2.3.4').data['protoPayload']
        assert resp.is_unusual_source(payload1) is True
        
        payload2 = make_cloud_event(caller_ip='compute.google.com').data['protoPayload']
        assert resp.is_unusual_source(payload2) is False

    @patch('src.sa_compromise_response.datetime')
    def test_is_suspicious_timing(self, mock_dt):
        mock_dt.now.return_value.hour = 2
        assert resp.is_suspicious_timing() is True
        mock_dt.now.return_value.hour = 12
        assert resp.is_suspicious_timing() is False

    @patch('src.sa_compromise_response.send_sa_alert')
    @patch('src.sa_compromise_response.remove_critical_roles')
    @patch('src.sa_compromise_response.disable_sa_keys')
    def test_execute_sa_response(self, mock_dis, mock_rem, mock_snd):
        resp.execute_sa_response("sa", "p", 10, {})
        mock_dis.assert_called_once()
        mock_rem.assert_called_once()
        mock_snd.assert_called_once()
        
        mock_dis.side_effect = Exception("Err")
        resp.execute_sa_response("sa", "p", 10, {}) # shouldn't raise

    @patch('src.sa_compromise_response.get_iam_client')
    @patch('src.sa_compromise_response.iam_admin_v1')
    def test_disable_sa_keys(self, mock_v1, mock_get_iam):
        mock_client = MagicMock()
        mock_get_iam.return_value = mock_client
        mock_key = MagicMock()
        
        # We need mock_v1.ServiceAccountKey.Type.USER_MANAGED to equal key.key_type
        mock_key.key_type = "USER_MANAGED"
        mock_v1.ServiceAccountKey.Type.USER_MANAGED = "USER_MANAGED"
        mock_key.name = "key1"
        
        mock_client.list_service_account_keys.return_value.keys = [mock_key]
        
        resp.disable_sa_keys("test_sa")
        mock_client.disable_service_account_key.assert_called_once_with(name="key1")

        mock_get_iam.side_effect = Exception("Err")
        resp.disable_sa_keys("test_sa") # should cover exception

    @patch('google.cloud.resourcemanager_v3.ProjectsClient')
    def test_remove_critical_roles(self, mock_rm_client):
        mock_client = MagicMock()
        mock_rm_client.return_value = mock_client
        
        mock_binding1 = MagicMock()
        mock_binding1.role = 'roles/editor'
        mock_binding1.members = ['serviceAccount:test_sa', 'user:other']
        
        mock_binding2 = MagicMock()
        mock_binding2.role = 'roles/viewer'
        mock_binding2.members = ['serviceAccount:test_sa']
        
        mock_client.get_iam_policy.return_value.bindings = [mock_binding1, mock_binding2]
        
        resp.remove_critical_roles("test_sa")
        mock_client.set_iam_policy.assert_called_once()
        
        # Test no changes branch
        mock_client.reset_mock()
        mock_client.get_iam_policy.return_value.bindings = [mock_binding2]
        resp.remove_critical_roles("test_sa")
        mock_client.set_iam_policy.assert_not_called()

        mock_rm_client.side_effect = Exception("Err")
        resp.remove_critical_roles("test_sa")

    @patch('src.sa_compromise_response.get_publisher')
    def test_send_sa_alert(self, mock_pub):
        resp.send_sa_alert("sa", "pr", 10, {})
        mock_pub.return_value.publish.assert_called_once()
        
        mock_pub.side_effect = Exception("Err")
        resp.send_sa_alert("sa", "pr", 10, {})

    @patch('src.sa_compromise_response.cloud_logging')
    def test_setup_logging(self, mock_cl):
        resp.setup_logging.configured = False
        resp.setup_logging()
        assert resp.setup_logging.configured is True
        
        # reset config to test exception fallback
        resp.setup_logging.configured = False
        mock_cl.Client.side_effect = Exception("Err")
        resp.setup_logging()
        assert resp.setup_logging.configured is True

    @patch('src.sa_compromise_response.iam_admin_v1')
    def test_get_iam_client(self, mock_v1):
        resp.iam_client = None
        client = resp.get_iam_client()
        assert client is not None

    @patch('src.sa_compromise_response.pubsub_v1')
    def test_get_publisher(self, mock_v1):
        resp.publisher = None
        client = resp.get_publisher()
        assert client is not None

