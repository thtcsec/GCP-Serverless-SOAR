import os
import json
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

os.environ['PROJECT_ID'] = 'test-project'
os.environ['ALERT_TOPIC'] = 'test-topic'
os.environ['EXFILTRATION_THRESHOLD'] = '1000'

import src.storage_exfil_response as resp

def make_cloud_event(method_name='storage.objects.get', 
                     bucket_name='test-bucket',
                     object_name='test-obj',
                     principal='attacker@example.com',
                     caller_ip='1.2.3.4'):
    return MagicMock(id='event-123', data={
        'protoPayload': {
            'methodName': method_name,
            'resourceName': f'projects/_/buckets/{bucket_name}/objects/{object_name}' if bucket_name else '',
            'authenticationInfo': {'principalEmail': principal},
            'request': {'callerIp': caller_ip}
        }
    })

class TestStorageExfilResponse:

    @patch('src.storage_exfil_response.setup_logging')
    @patch('src.storage_exfil_response.analyze_exfiltration_patterns')
    @patch('src.storage_exfil_response.integrations.ScoringEngine')
    @patch('src.storage_exfil_response.integrations.ThreatIntelService')
    @patch('src.storage_exfil_response.execute_exfiltration_response')
    def test_storage_exfil_responder(self, mock_exec, mock_intel, mock_scoring, mock_analyze, mock_setup):
        mock_intel.return_value.get_ip_report.return_value = {}
        mock_scoring.return_value.calculate_risk_score.return_value = {"decision": "AUTO_ISOLATE", "risk_score": 85}
        mock_analyze.return_value = {'is_exfiltration': True, 'risk_score': 10}
        
        event = make_cloud_event()
        resp.storage_exfil_responder(event)
        mock_exec.assert_called_once()

    @patch('src.storage_exfil_response.integrations.ScoringEngine')
    @patch('src.storage_exfil_response.integrations.ThreatIntelService')
    def test_process_storage_event_detected(self, mock_intel, mock_scoring):
        mock_intel.return_value.get_ip_report.return_value = {}
        mock_scoring.return_value.calculate_risk_score.return_value = {"decision": "AUTO_ISOLATE", "risk_score": 90}
        
        payload = make_cloud_event().data['protoPayload']
        with patch('src.storage_exfil_response.analyze_exfiltration_patterns', return_value={'is_exfiltration': True, 'risk_score': 10}):
            with patch('src.storage_exfil_response.execute_exfiltration_response') as mock_exec:
                resp.process_storage_event(payload)
                mock_exec.assert_called_once()

    def test_extract_bucket_name(self):
        assert resp.extract_bucket_name('projects/_/buckets/b/objects/o') == 'b'
        assert resp.extract_bucket_name('invalid') is None

    @patch('src.storage_exfil_response.get_storage_client')
    def test_block_user_bucket_access(self, mock_client):
        mock_bucket = MagicMock()
        mock_client.return_value.bucket.return_value = mock_bucket
        mock_policy = MagicMock()
        mock_policy.bindings = [{'role': 'roles/viewer', 'members': ['user:attacker@example.com']}]
        mock_bucket.get_iam_policy.return_value = mock_policy
        
        resp.block_user_bucket_access("b", "attacker@example.com")
        mock_bucket.set_iam_policy.assert_called_once()

    @patch('src.storage_exfil_response.get_publisher')
    def test_send_exfiltration_alert(self, mock_pub):
        mock_pub.return_value.publish.return_value.result.return_value = "id"
        resp.send_exfiltration_alert("b", "p", "ip", {}, {"risk_score": 90}, {})
        mock_pub.return_value.publish.assert_called_once()
