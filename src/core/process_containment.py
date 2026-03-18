"""
GCP SOAR — Process-Level Containment via Compute Engine
Enables granular containment by listing and killing malicious processes
on GCE instances using startup-script metadata or OS Login,
instead of the coarse-grained Network isolation approach.

Containment Hierarchy: Function > Process > Permissions > Network
"""

from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger("gcp-soar.process_containment")


class ProcessContainment:
    """Manage process-level containment on GCE instances via metadata script execution."""

    def __init__(self, compute_client: Any) -> None:
        self._compute = compute_client

    def list_processes(self, project: str, zone: str, instance: str) -> list[dict[str, str]]:
        """List running processes on the target GCE instance via serial port output."""
        command = "ps aux --sort=-%cpu | head -50"
        output = self._run_command(project, zone, instance, command)
        if not output:
            return []

        processes: list[dict[str, str]] = []
        lines = output.strip().split("\n")
        for line in lines[1:]:  # Skip header
            parts = line.split(None, 10)
            if len(parts) >= 11:
                processes.append(
                    {
                        "user": parts[0],
                        "pid": parts[1],
                        "cpu": parts[2],
                        "mem": parts[3],
                        "command": parts[10],
                    }
                )
        return processes

    def kill_process(self, project: str, zone: str, instance: str, pid: str) -> bool:
        """Kill a specific process by PID on the target instance."""
        command = f"kill -9 {pid} && echo 'KILLED' || echo 'FAILED'"
        output = self._run_command(project, zone, instance, command)
        return output is not None and "KILLED" in output

    def kill_by_name(self, project: str, zone: str, instance: str, process_name: str) -> bool:
        """Kill all processes matching a name (e.g. 'xmrig', 'cryptominer')."""
        safe_name = process_name.replace("'", "")
        command = f"pkill -9 -f '{safe_name}' && echo 'KILLED' || echo 'NO_MATCH'"
        output = self._run_command(project, zone, instance, command)
        return output is not None and "KILLED" in output

    def quarantine_file(self, project: str, zone: str, instance: str, file_path: str) -> bool:
        """Move a suspicious file to a quarantine directory."""
        commands = [
            "mkdir -p /var/quarantine",
            f"chmod 000 '{file_path}'",
            f"mv '{file_path}' /var/quarantine/",
        ]
        command = " && ".join(commands) + " && echo 'QUARANTINED'"
        output = self._run_command(project, zone, instance, command)
        return output is not None and "QUARANTINED" in output

    def get_containment_report(self, project: str, zone: str, instance: str) -> dict[str, Any]:
        """Generate a containment status report for the instance."""
        processes = self.list_processes(project, zone, instance)

        suspicious_keywords = [
            "xmrig",
            "cryptominer",
            "minerd",
            "coinhive",
            "kinsing",
            "kdevtmpfsi",
            "ld-linux",
        ]
        suspicious = [p for p in processes if any(kw in p.get("command", "").lower() for kw in suspicious_keywords)]

        return {
            "instance": instance,
            "project": project,
            "zone": zone,
            "total_processes": len(processes),
            "suspicious_processes": suspicious,
            "suspicious_count": len(suspicious),
            "top_cpu_processes": processes[:5],
        }

    def _run_command(self, project: str, zone: str, instance: str, command: str) -> str | None:
        """Execute a shell command on GCE via startup-script metadata."""
        try:
            # Set startup-script metadata to execute command
            script = f"#!/bin/bash\n{command} > /tmp/soar_output.txt 2>&1"

            self._compute.instances().setMetadata(
                project=project,
                zone=zone,
                instance=instance,
                body={
                    "items": [
                        {"key": "startup-script", "value": script},
                    ],
                },
            ).execute()

            # Wait for execution
            time.sleep(5)

            # Read output via serial port (port 1)
            serial_output = (
                self._compute.instances()
                .getSerialPortOutput(
                    project=project,
                    zone=zone,
                    instance=instance,
                    port=1,
                )
                .execute()
            )

            return serial_output.get("contents", "")

        except Exception as e:
            logger.error(f"GCE command execution error on {instance} (project={project}, zone={zone}): {e}")
            return None
