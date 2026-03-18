"""
Enterprise SOAR GCP - Isolation Worker
Long-running container for GCP instance isolation operations
"""

import logging
import os
import time
from datetime import UTC, datetime

from flask import Flask, jsonify, request
from google.cloud import compute_v1, workflows_v1

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO")),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# GCP clients
compute_client = compute_v1.InstancesClient()
workflows_client = workflows_v1.WorkflowsClient()

# Configuration
PROJECT_ID = os.environ.get("PROJECT_ID")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "production")
ISOLATION_FIREWALL_NAME = os.environ.get("ISOLATION_FIREWALL_NAME")


class GCPIsolationWorker:
    """Enterprise-grade GCP isolation worker"""

    def __init__(self):
        self.active_operations = {}
        self.operation_counter = 0

    def isolate_instance(self, instance_name, zone, operation_id=None):
        """
        Isolate GCP instance using firewall rules

        Args:
            instance_name (str): GCP instance name
            zone (str): GCP zone
            operation_id (str): Unique operation identifier

        Returns:
            dict: Operation result
        """
        if not operation_id:
            self.operation_counter += 1
            operation_id = f"isolation-{int(time.time())}-{self.operation_counter}"

        try:
            logger.info(f"Starting isolation operation {operation_id} for instance {instance_name} in zone {zone}")

            # Track operation
            self.active_operations[operation_id] = {
                "instance_name": instance_name,
                "zone": zone,
                "status": "in_progress",
                "start_time": datetime.now(UTC).isoformat(),
                "steps": [],
            }

            # Step 1: Validate instance exists
            self._validate_instance(instance_name, zone, operation_id)

            # Step 2: Get current network tags
            current_tags = self._get_instance_tags(instance_name, zone, operation_id)

            # Step 3: Create isolation firewall rule
            firewall_rule = self._create_isolation_firewall(instance_name, zone, operation_id)

            # Step 4: Apply isolation tag to instance
            self._apply_isolation_tag(instance_name, zone, operation_id)

            # Step 5: Verify isolation
            self._verify_isolation(instance_name, zone, operation_id)

            # Mark operation complete
            self.active_operations[operation_id]["status"] = "completed"
            self.active_operations[operation_id]["end_time"] = datetime.now(UTC).isoformat()

            result = {
                "operation_id": operation_id,
                "instance_name": instance_name,
                "zone": zone,
                "isolation_successful": True,
                "firewall_rule": firewall_rule,
                "original_tags": current_tags,
                "isolation_timestamp": datetime.now(UTC).isoformat(),
                "steps": self.active_operations[operation_id]["steps"],
            }

            logger.info(f"Successfully completed isolation operation {operation_id}")
            return result

        except Exception as e:
            logger.error(f"Isolation operation {operation_id} failed: {str(e)}")

            # Mark operation failed
            if operation_id in self.active_operations:
                self.active_operations[operation_id]["status"] = "failed"
                self.active_operations[operation_id]["error"] = str(e)
                self.active_operations[operation_id]["end_time"] = datetime.now(UTC).isoformat()

            return {
                "operation_id": operation_id,
                "instance_name": instance_name,
                "zone": zone,
                "isolation_successful": False,
                "error": str(e),
                "timestamp": datetime.now(UTC).isoformat(),
            }

    def _validate_instance(self, instance_name, zone, operation_id):
        """Validate that the instance exists and is accessible"""
        try:
            instance = compute_client.get(project=PROJECT_ID, zone=zone, instance=instance_name)

            state = instance.status.lower()

            if state == "terminated":
                raise ValueError(f"Instance {instance_name} is already terminated")

            if state == "stopping":
                raise ValueError(f"Instance {instance_name} is stopping, cannot isolate")

            self._log_step(
                operation_id, "validate_instance", "success", f"Instance {instance_name} validated (state: {state})"
            )

        except Exception as e:
            self._log_step(operation_id, "validate_instance", "failed", str(e))
            raise

    def _get_instance_tags(self, instance_name, zone, operation_id):
        """Get current instance network tags"""
        try:
            instance = compute_client.get(project=PROJECT_ID, zone=zone, instance=instance_name)

            current_tags = list(instance.tags.items) if instance.tags else []

            self._log_step(operation_id, "get_instance_tags", "success", f"Current tags: {current_tags}")
            return current_tags

        except Exception as e:
            self._log_step(operation_id, "get_instance_tags", "failed", str(e))
            raise

    def _create_isolation_firewall(self, instance_name, zone, operation_id):
        """Create firewall rule for isolation"""
        try:
            firewall_rule_name = f"{ISOLATION_FIREWALL_NAME}-{instance_name}"

            # Get instance network details
            instance = compute_client.get(project=PROJECT_ID, zone=zone, instance=instance_name)

            network_url = instance.network_interfaces[0].network

            # Create firewall rule that denies all traffic
            firewall_rule = compute_v1.Firewall()
            firewall_rule.name = firewall_rule_name
            firewall_rule.description = f"SOAR isolation rule for instance {instance_name}"
            firewall_rule.network = network_url
            firewall_rule.direction = compute_v1.Firewall.Direction.INGRESS
            firewall_rule.priority = 1
            firewall_rule.denied = [
                compute_v1.Firewall.Denied(ip_protocol="TCP"),
                compute_v1.Firewall.Denied(ip_protocol="UDP"),
                compute_v1.Firewall.Denied(ip_protocol="ICMP"),
            ]
            firewall_rule.target_tags = [f"isolated-{instance_name}"]

            # Create the firewall rule
            operation = compute_client.insert_firewall(project=PROJECT_ID, firewall_resource=firewall_rule)

            # Wait for operation to complete
            operation.result()

            self._log_step(operation_id, "create_firewall", "success", f"Created firewall rule {firewall_rule_name}")
            return firewall_rule_name

        except Exception as e:
            self._log_step(operation_id, "create_firewall", "failed", str(e))
            raise

    def _apply_isolation_tag(self, instance_name, zone, operation_id):
        """Apply isolation tag to instance"""
        try:
            # Get current instance
            instance = compute_client.get(project=PROJECT_ID, zone=zone, instance=instance_name)

            # Add isolation tag
            tags = compute_v1.Tags()
            tags.items = instance.tags.items + [f"isolated-{instance_name}"]
            tags.fingerprint = instance.tags.fingerprint

            # Update instance tags
            operation = compute_client.set_tags(
                project=PROJECT_ID, zone=zone, instance=instance_name, tags_resource=tags
            )

            # Wait for operation to complete
            operation.result()

            self._log_step(
                operation_id, "apply_isolation_tag", "success", f"Applied isolation tag to instance {instance_name}"
            )

        except Exception as e:
            self._log_step(operation_id, "apply_isolation_tag", "failed", str(e))
            raise

    def _verify_isolation(self, instance_name, zone, operation_id, max_attempts=3):
        """Verify that instance is properly isolated"""
        for attempt in range(max_attempts):
            try:
                instance = compute_client.get(project=PROJECT_ID, zone=zone, instance=instance_name)

                # Check if isolation tag is applied
                isolation_tag = f"isolated-{instance_name}"
                if isolation_tag in instance.tags.items:
                    self._log_step(
                        operation_id, "verify_isolation", "success", f"Isolation verified (attempt {attempt + 1})"
                    )
                    return True

                logger.warning(f"Isolation verification attempt {attempt + 1} failed")
                time.sleep(2)

            except Exception as e:
                logger.warning(f"Error during isolation verification attempt {attempt + 1}: {str(e)}")
                if attempt == max_attempts - 1:
                    raise
                time.sleep(2)

        raise RuntimeError("Failed to verify instance isolation")

    def _log_step(self, operation_id, step_name, status, details):
        """Log operation step details"""
        if operation_id in self.active_operations:
            self.active_operations[operation_id]["steps"].append(
                {
                    "step": step_name,
                    "status": status,
                    "details": details,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            )

    def get_operation_status(self, operation_id):
        """Get status of a specific operation"""
        return self.active_operations.get(operation_id, {"status": "not_found"})

    def get_active_operations(self):
        """Get all active operations"""
        return self.active_operations


# Initialize worker
worker = GCPIsolationWorker()


# Flask routes
@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify(
        {
            "status": "healthy",
            "timestamp": datetime.now(UTC).isoformat(),
            "environment": ENVIRONMENT,
            "active_operations": len(worker.active_operations),
        }
    )


@app.route("/isolate", methods=["POST"])
def isolate_instance():
    """Isolate instance endpoint"""
    try:
        data = request.get_json()

        if not data or "instance_name" not in data or "zone" not in data:
            return jsonify({"error": "instance_name and zone are required"}), 400

        instance_name = data["instance_name"]
        zone = data["zone"]
        operation_id = data.get("operation_id")

        result = worker.isolate_instance(instance_name, zone, operation_id)

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Error in isolate endpoint: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/status/<operation_id>", methods=["GET"])
def get_operation_status(operation_id):
    """Get operation status endpoint"""
    try:
        status = worker.get_operation_status(operation_id)

        if status.get("status") == "not_found":
            return jsonify({"error": "Operation not found"}), 404

        return jsonify(status), 200

    except Exception as e:
        logger.error(f"Error in status endpoint: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/operations", methods=["GET"])
def get_active_operations():
    """Get all active operations endpoint"""
    try:
        operations = worker.get_active_operations()
        return jsonify(operations), 200

    except Exception as e:
        logger.error(f"Error in operations endpoint: {str(e)}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    logger.info("Starting SOAR GCP Isolation Worker")
    app.run(host="0.0.0.0", port=8080, debug=False)
