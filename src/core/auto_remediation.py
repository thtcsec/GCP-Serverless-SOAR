"""
GCP SOAR — Auto-Remediation Patching
Automatically patches vulnerable packages on compromised GCE instances
by executing commands via startup-script metadata after containment.
"""

import logging
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Known CVE → package mappings for auto-remediation
VULNERABILITY_PATCH_MAP: Dict[str, List[str]] = {
    "openssl": ["openssl", "libssl-dev"],
    "log4j": ["liblog4j2-java"],
    "curl": ["curl", "libcurl4"],
    "sudo": ["sudo"],
    "polkit": ["policykit-1"],
    "apache": ["apache2"],
    "nginx": ["nginx"],
    "ssh": ["openssh-server", "openssh-client"],
}


class AutoRemediation:
    """Automated vulnerability patching via GCE metadata scripts."""

    def __init__(self, client: Optional[Any] = None,
                 project_id: str = "", zone: str = "us-central1-a"):
        self.project_id = project_id
        self.zone = zone
        if client is None:
            from google.cloud import compute_v1  # type: ignore
            self.client = compute_v1.InstancesClient()
        else:
            self.client = client

    def patch_instance(
        self,
        instance_name: str,
        vulnerability_keywords: List[str],
    ) -> Dict[str, Any]:
        """
        Patch a GCE instance by upgrading packages related to
        detected vulnerabilities.

        Args:
            instance_name: The GCE instance to patch.
            vulnerability_keywords: List of keywords from
                the vulnerability scan (e.g. ["openssl", "curl"]).

        Returns:
            Dict with patch results.
        """
        packages_to_patch: List[str] = []
        for keyword in vulnerability_keywords:
            kw = keyword.lower()
            for vuln_key, pkgs in VULNERABILITY_PATCH_MAP.items():
                if vuln_key in kw:
                    packages_to_patch.extend(pkgs)

        packages_to_patch = list(set(packages_to_patch))

        if not packages_to_patch:
            return {
                "status": "skipped",
                "instance_name": instance_name,
                "reason": "No matching packages found for given keywords.",
            }

        patch_script = (
            "#!/bin/bash\n"
            "apt-get update -qq && "
            f"apt-get install -y --only-upgrade {' '.join(packages_to_patch)}\n"
        )

        try:
            from google.cloud.compute_v1.types import (  # type: ignore
                Items,
                Metadata,
                SetMetadataInstanceRequest,
            )

            metadata = Metadata(
                items=[Items(key="startup-script", value=patch_script)]
            )
            request = SetMetadataInstanceRequest(
                instance=instance_name,
                project=self.project_id,
                zone=self.zone,
                metadata_resource=metadata,
            )
            self.client.set_metadata(request=request)

            logger.info(
                "Auto-remediation script sent to %s: %s",
                instance_name,
                packages_to_patch,
            )

            return {
                "status": "sent",
                "instance_name": instance_name,
                "packages_patched": packages_to_patch,
                "timestamp": time.time(),
            }

        except Exception as exc:
            logger.error("GCE patch command failed: %s", exc)
            return {
                "status": "error",
                "instance_name": instance_name,
                "error": str(exc),
            }
