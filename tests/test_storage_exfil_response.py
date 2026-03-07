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
    @patch('src.storage_exfil_response.process_storage_event')
    def test_storage_exfil_responder_valid(self, mock_process, mock_setup):
        event = make_cloud_event()
        resp.storage_exfil_responder(event)
        mock_process.assert_called_once()
        
    def test_storage_exfil_responder_invalid(self):
        # Missing protoPayload
        event = MagicMock(id='1', data={})
        resp.storage_exfil_responder(event)
        
    @patch('src.storage_exfil_response.process_storage_event', side_effect=Exception('Test Error'))
    def test_storage_exfil_responder_error(self, mock_process):
        resp.storage_exfil_responder(make_cloud_event())

    @patch('src.storage_exfil_response.execute_exfiltration_response')
    def test_process_storage_event(self, mock_exec):
        payload = make_cloud_event().data['protoPayload']
        
        # Test low risk
        with patch('src.storage_exfil_response.analyze_exfiltration_patterns', return_value={'is_exfiltration': False}):
            resp.process_storage_event(payload)
            mock_exec.assert_not_called()
            
        # Test high risk
        with patch('src.storage_exfil_response.analyze_exfiltration_patterns', return_value={'is_exfiltration': True}):
            resp.process_storage_event(payload)
            mock_exec.assert_called_once()
            
        # Test non matching method
        payload_non_match = make_cloud_event('storage.buckets.create').data['protoPayload']
        resp.process_storage_event(payload_non_match)
        
        # Test missing bucket name
        payload_no_bucket = make_cloud_event(bucket_name=None).data['protoPayload']
        resp.process_storage_event(payload_no_bucket)

    def test_extract_bucket_name(self):
        assert resp.extract_bucket_name('projects/_/buckets/b/objects/o') == 'b'
        assert resp.extract_bucket_name('invalid') is None

    def test_extract_object_name(self):
        assert resp.extract_object_name('projects/_/buckets/b/objects/o') == 'o'
        assert resp.extract_object_name('invalid') is None

    @patch('src.storage_exfil_response.get_recent_storage_logs')
    @patch('src.storage_exfil_response.is_suspicious_timing')
    @patch('src.storage_exfil_response.is_rapid_succession')
    def test_analyze_exfiltration_patterns(self, mock_rapid, mock_timing, mock_logs):
        mock_rapid.return_value = True # +3
        mock_timing.return_value = True # +2
        
        # 4 unique ips -> +2
        # total_bytes > 1000 -> +5
        # access_count > 1000 -> +3 
        # Total score should be 15
        logs = []
        for i in range(1001):
            ip = f"1.1.1.{i%5}" # 5 unique IPs
            logs.append({'callerIp': ip, 'metadata': {'size': '2'}}) # total_bytes = 2002
            
        mock_logs.return_value = logs
        
        analysis = resp.analyze_exfiltration_patterns("test@t.com", "b", "ip")
        assert analysis['is_exfiltration'] is True
        assert analysis['risk_score'] == 15
        assert analysis['access_count'] == 1001
        assert analysis['total_bytes'] == 2002
        assert len(analysis['unique_ips']) == 5
        
        # Error case
        mock_logs.side_effect = Exception("Err")
        analysis2 = resp.analyze_exfiltration_patterns("test@t.com", "b", "ip")
        assert analysis2['is_exfiltration'] is False

    @patch('src.storage_exfil_response.datetime')
    def test_get_recent_storage_logs(self, mock_dt):
        mock_dt.now.return_value = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
        res = resp.get_recent_storage_logs("p", "b")
        assert res == []

    def test_get_recent_storage_logs_error(self):
        with patch('src.storage_exfil_response.datetime', side_effect=Exception("Err")):
            res = resp.get_recent_storage_logs("p", "b")
            assert res == []

    def test_estimate_total_bytes(self):
        logs = [{'metadata': {'size': '20'}}, {}]
        assert resp.estimate_total_bytes(logs) == 20 + 1024*1024
        
    def test_is_suspicious_timing(self):
        assert resp.is_suspicious_timing([]) is False
        logs = [
            {'timestamp': '2026-03-01T23:30:00Z'},
            {'timestamp': '2026-03-01T02:30:00Z'},
            {'timestamp': '2026-03-01T12:30:00Z'}
        ]
        # 2 out of 3 are unusual -> >30%
        assert resp.is_suspicious_timing(logs) is True
        
        logs2 = [{'timestamp': '2026-03-01T12:30:00Z'}]
        assert resp.is_suspicious_timing(logs2) is False

    def test_is_rapid_succession(self):
        assert resp.is_rapid_succession([]) is False
        
        # 55 logs with identical time -> rapid series
        logs = []
        for _ in range(55):
            logs.append({'timestamp': '2026-03-01T12:00:00Z'})
        assert resp.is_rapid_succession(logs) is True

    @patch('src.storage_exfil_response.send_exfiltration_alert')
    @patch('src.storage_exfil_response.create_forensic_snapshot')
    @patch('src.storage_exfil_response.enable_bucket_protections')
    @patch('src.storage_exfil_response.block_user_bucket_access')
    def test_execute_exfiltration_response(self, mock_block, mock_prot, mock_for, mock_alert):
        resp.execute_exfiltration_response("b", "p", "ip", {})
        mock_block.assert_called_once()
        mock_prot.assert_called_once()
        mock_for.assert_called_once()
        mock_alert.assert_called_once()
        
        mock_block.side_effect = Exception("Err")
        resp.execute_exfiltration_response("b", "p", "ip", {})

    @patch('src.storage_exfil_response.get_storage_client')
    def test_block_user_bucket_access(self, mock_client):
        mock_bucket = MagicMock()
        mock_client.return_value.bucket.return_value = mock_bucket
        
        mock_policy = MagicMock()
        mock_policy.bindings = [
            {'role': 'roles/viewer', 'members': ['user:attacker@example.com', 'user:other@example.com']}
        ]
        mock_bucket.get_iam_policy.return_value = mock_policy
        
        resp.block_user_bucket_access("b", "attacker@example.com")
        mock_bucket.set_iam_policy.assert_called_once()
        assert 'user:attacker@example.com' not in mock_policy.bindings[0]['members']
        
        # Service account parsing
        mock_policy.bindings = [
            {'role': 'roles/viewer', 'members': ['serviceAccount:attacker@test.gserviceaccount.com']}
        ]
        mock_bucket.get_iam_policy.return_value = mock_policy
        mock_bucket.reset_mock()
        resp.block_user_bucket_access("b", "attacker@test.gserviceaccount.com")
        mock_bucket.set_iam_policy.assert_called_once()

        # No direct bindings
        mock_policy.bindings = []
        mock_bucket.get_iam_policy.return_value = mock_policy
        mock_bucket.reset_mock()
        resp.block_user_bucket_access("b", "attacker@example.com")
        mock_bucket.set_iam_policy.assert_not_called()

        # Error
        mock_client.side_effect = Exception("Err")
        resp.block_user_bucket_access("b", "a")

    @patch('src.storage_exfil_response.get_storage_client')
    def test_enable_bucket_protections(self, mock_client):
        mock_bucket = MagicMock()
        mock_client.return_value.bucket.return_value = mock_bucket
        
        mock_bucket.versioning_enabled = False
        # Mock iam_configuration properly
        mock_iam_config = MagicMock()
        mock_iam_config.uniform_bucket_level_access_enabled = False
        mock_bucket.iam_configuration = mock_iam_config
        
        resp.enable_bucket_protections("b")
        assert mock_bucket.versioning_enabled is True
        assert mock_bucket.retention_period == 30
        assert mock_iam_config.uniform_bucket_level_access_enabled is True
        
        # Test retention period property failure
        type(mock_bucket).retention_period = property(lambda self: 10, lambda self, v: self._raise_err())
        def raise_err(self): raise Exception("Err")
        mock_bucket._raise_err = lambda: raise_err(mock_bucket)
        
        resp.enable_bucket_protections("b") # should catch and continue

        mock_client.side_effect = Exception("Err2")
        resp.enable_bucket_protections("b")

    @patch('src.storage_exfil_response.get_storage_client')
    def test_create_forensic_snapshot(self, mock_client):
        mock_source = MagicMock()
        mock_source.time_created = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
        mock_source.updated = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
        
        mock_dest = MagicMock()
        mock_blob = MagicMock()
        mock_dest.blob.return_value = mock_blob
        
        mock_client.return_value.bucket.side_effect = [mock_source, mock_dest]
        
        resp.create_forensic_snapshot("b", "p", {})
        mock_blob.upload_from_string.assert_called_once()

        mock_client.side_effect = Exception("Err")
        resp.create_forensic_snapshot("b", "p", {})

    @patch('src.storage_exfil_response.get_publisher')
    def test_send_exfiltration_alert(self, mock_pub):
        mock_future = MagicMock()
        mock_pub.return_value.publish.return_value = mock_future
        
        resp.send_exfiltration_alert("b", "p", "ip", {})
        mock_pub.return_value.publish.assert_called_once()
        mock_future.result.assert_called_once()
        
        mock_pub.side_effect = Exception("Err")
        resp.send_exfiltration_alert("b", "p", "ip", {})

    @patch('src.storage_exfil_response.cloud_logging')
    def test_setup_logging(self, mock_cl):
        resp.setup_logging.configured = False
        resp.setup_logging()
        assert resp.setup_logging.configured is True
        
        resp.setup_logging.configured = False
        mock_cl.Client.side_effect = Exception("Err")
        resp.setup_logging()
        assert resp.setup_logging.configured is True

    @patch('src.storage_exfil_response.storage')
    def test_get_storage_client(self, mock_s):
        resp.storage_client = None
        client = resp.get_storage_client()
        assert client is not None

    @patch('src.storage_exfil_response.pubsub_v1')
    def test_get_publisher(self, mock_v1):
        resp.publisher = None
        client = resp.get_publisher()
        assert client is not None
