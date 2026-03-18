"""Tests for GCP Process Containment via Compute Engine."""

from unittest.mock import MagicMock, patch

import pytest

from src.core.process_containment import ProcessContainment


class TestProcessContainment:
    @pytest.fixture
    def compute_client(self):
        return MagicMock()

    @pytest.fixture
    def containment(self, compute_client):
        return ProcessContainment(compute_client)

    @pytest.fixture
    def mock_ps_output(self):
        return (
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root         1  0.0  0.1  16968  3072 ?        Ss   00:00   0:01 /sbin/init\n"
            "evil      1337 95.0 10.0 999999 99999 ?        R    01:00   5:00 /tmp/xmrig --pool pool.minexmr.com\n"
            "www-data   500  2.0  1.0  50000  5000 ?        S    00:05   0:10 /usr/sbin/apache2\n"
        )

    def _setup_compute_success(self, compute_client, output):
        instances = compute_client.instances.return_value
        instances.setMetadata.return_value.execute.return_value = {}
        instances.getSerialPortOutput.return_value.execute.return_value = {"contents": output}

    def test_list_processes(self, containment, compute_client, mock_ps_output):
        self._setup_compute_success(compute_client, mock_ps_output)
        with patch("src.core.process_containment.time.sleep"):
            processes = containment.list_processes("my-project", "us-central1-a", "vm-1")
        assert len(processes) == 3
        assert processes[1]["pid"] == "1337"

    def test_kill_process_success(self, containment, compute_client):
        self._setup_compute_success(compute_client, "KILLED")
        with patch("src.core.process_containment.time.sleep"):
            result = containment.kill_process("my-project", "us-central1-a", "vm-1", "1337")
        assert result is True

    def test_kill_process_failure(self, containment, compute_client):
        self._setup_compute_success(compute_client, "FAILED")
        with patch("src.core.process_containment.time.sleep"):
            result = containment.kill_process("my-project", "us-central1-a", "vm-1", "1337")
        assert result is False

    def test_kill_by_name(self, containment, compute_client):
        self._setup_compute_success(compute_client, "KILLED")
        with patch("src.core.process_containment.time.sleep"):
            result = containment.kill_by_name("my-project", "us-central1-a", "vm-1", "xmrig")
        assert result is True

    def test_quarantine_file(self, containment, compute_client):
        self._setup_compute_success(compute_client, "QUARANTINED")
        with patch("src.core.process_containment.time.sleep"):
            result = containment.quarantine_file("my-project", "us-central1-a", "vm-1", "/tmp/malware.bin")
        assert result is True

    def test_containment_report(self, containment, compute_client, mock_ps_output):
        self._setup_compute_success(compute_client, mock_ps_output)
        with patch("src.core.process_containment.time.sleep"):
            report = containment.get_containment_report("my-project", "us-central1-a", "vm-1")
        assert report["instance"] == "vm-1"
        assert report["suspicious_count"] == 1

    def test_compute_exception_returns_none(self, containment, compute_client):
        compute_client.instances.side_effect = Exception("API error")
        result = containment._run_command("proj", "zone", "vm", "echo test")
        assert result is None
