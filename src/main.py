import base64
import json
import logging
import os
import urllib.request
from datetime import UTC, datetime

import functions_framework
from google.cloud import compute_v1
from google.cloud import logging as cloud_logging

import src.integrations as integrations

compute_client = None
disks_client = None
snapshots_client = None

ISOLATION_TAG = "isolated-vm"
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")

logger = logging.getLogger("soar-ir-logger")
logger.setLevel(logging.INFO)


def setup_logging():
    if getattr(setup_logging, "configured", False):
        return
    try:
        client = cloud_logging.Client()
        client.setup_logging()
    except Exception:
        logging.basicConfig(level=logging.INFO)
    setup_logging.configured = True


def get_compute_client():
    global compute_client
    if compute_client is None:
        compute_client = compute_v1.InstancesClient()
    return compute_client


def get_disks_client():
    global disks_client
    if disks_client is None:
        disks_client = compute_v1.DisksClient()
    return disks_client


def get_snapshots_client():
    global snapshots_client
    if snapshots_client is None:
        snapshots_client = compute_v1.SnapshotsClient()
    return snapshots_client


@functions_framework.cloud_event
def soar_responder(cloud_event):
    """Entry point for the Cloud Function triggered by Pub/Sub."""
    setup_logging()
    logger.info(f"Received Cloud Event ID: {cloud_event['id']}")

    if not cloud_event.data or "message" not in cloud_event.data:
        logger.error("Invalid event format")
        return

    # Decode Pub/Sub message
    message_data = base64.b64decode(cloud_event.data["message"]["data"]).decode("utf-8")
    try:
        finding = json.loads(message_data)
        process_finding(finding)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse finding JSON: {str(e)}")


def process_finding(finding):
    setup_logging()
    severity = finding.get("severity", "")
    category = finding.get("category", "")
    resource_name = finding.get(
        "resourceName", ""
    )  # Format: //compute.googleapis.com/projects/.../instances/instance-id
    finding_id = finding.get("name", "unknown-finding-id").split("/")[-1]

    logger.info(  # noqa: E501
        f"Processing SCC Finding - ID: {finding_id}, Category: {category}, Severity: {severity}, Resource: {resource_name}"  # noqa: E501
    )

    if severity not in ["HIGH", "CRITICAL"]:
        logger.info(f"Ignoring finding with severity {severity}. Only HIGH or CRITICAL are processed.")
        return

    allowed_categories = ["Cryptocurrency mining", "Backdoor", "Malware"]
    if not any(cat in category for cat in allowed_categories):
        logger.info(f"Ignoring category {category}. Not in target threat list.")
        return

    if not resource_name or "/instances/" not in resource_name:
        logger.warning("Resource is not a Compute Engine instance or is malformed.")
        return

    # Extract project, zone, instance from resource_name
    # Example format: //compute.googleapis.com/projects/my-project/zones/us-central1-a/instances/my-instance
    parts = resource_name.split("/")
    try:
        project_id = parts[4]
        zone = parts[6]
        instance_name = parts[8]
    except IndexError:
        logger.error(f"Failed to parse resource name: {resource_name}")
        return

    logger.info(
        f"Executing SOAR playbook on instance {instance_name} in {zone}",
        extra={
            "json_fields": {
                "action": "SOAR_TRIGGER",
                "instance": instance_name,
                "zone": zone,
                "threat": category,
                "finding_id": finding_id,
            }
        },
    )

    # --- THREAT INTEL ENRICHMENT & SCORING ---
    source_ip = None
    indicator = finding.get("indicator", {})
    ip_addresses = indicator.get("ipAddresses", [])
    if ip_addresses:
        source_ip = ip_addresses[0]

    if not source_ip:
        connections = finding.get("connections", [])
        for conn in connections:
            remote_ip = conn.get("destinationIp") or conn.get("sourceIp")
            if remote_ip:
                source_ip = remote_ip
                break

    risk_data = {"risk_score": 0.0, "decision": "AUTO_ISOLATE"}
    intel_report = {}

    if source_ip:
        logger.info(f"Enriching GCP finding with Intel for IP: {source_ip}")
        intel_service = integrations.ThreatIntelService()
        intel_report = intel_service.get_ip_report(source_ip)

        scoring_engine = integrations.ScoringEngine()
        # Scale severity: SCC HIGH -> 8.0, CRITICAL -> 10.0
        base_severity = 10.0 if severity == "CRITICAL" else 8.0
        risk_data = scoring_engine.calculate_risk_score(intel_report, base_severity)

        logger.info(f"Scoring Result: {json.dumps(risk_data)}")

        if risk_data["decision"] == "IGNORE":
            logger.info("Risk Score too low. Skipping remediation.")
            return

        if risk_data["decision"] == "REQUIRE_APPROVAL":
            logger.info("Requires manual approval.")
            send_slack_alert(
                project_id,
                zone,
                instance_name,
                category,
                severity,
                finding_id,
                risk_data,
                intel_report,
                approved=False,
            )
            return

    # Execute response playbook (AUTO_ISOLATE)
    try:
        isolate_instance(project_id, zone, instance_name)
        detach_service_account(project_id, zone, instance_name)
        block_project_ssh_keys(project_id, zone, instance_name)
        take_snapshot(project_id, zone, instance_name, category)
        stop_instance(project_id, zone, instance_name)

        logger.info(
            f"SOAR Playbook completed successfully for {instance_name}",
            extra={
                "json_fields": {
                    "action": "SOAR_COMPLETE",
                    "instance": instance_name,
                    "status": "success",
                    "finding_id": finding_id,
                }
            },
        )

        send_slack_alert(
            project_id,
            zone,
            instance_name,
            category,
            severity,
            finding_id,
            risk_data,
            intel_report,
            approved=True,
        )

    except Exception as e:
        logger.error(
            f"Failed to execute SOAR playbook: {str(e)}",
            extra={"json_fields": {"action": "SOAR_ERROR", "error": str(e), "finding_id": finding_id}},
        )


def send_slack_alert(
    project_id,
    zone,
    instance_name,
    category,
    severity,
    finding_id,
    risk_data=None,
    intel_report=None,
    approved=True,
):
    if not SLACK_WEBHOOK_URL:
        logger.error("SLACK_WEBHOOK_URL not configured. Cannot send Slack alert.")
        return

    action_status = "✅ Remediated (Auto-Isolated)" if approved else "⏳ PENDING APPROVAL (High Risk)"

    score_fields = []
    if risk_data:
        score_fields = [
            {"type": "mrkdwn", "text": f"*Risk Score:*\n{risk_data['risk_score']}/100"},
            {"type": "mrkdwn", "text": f"*Decision:*\n{risk_data['decision']}"},
            {
                "type": "mrkdwn",
                "text": f"*VT Malicious:*\n{risk_data['breakdown'].get('vt_malicious', 0)}",
            },
            {
                "type": "mrkdwn",
                "text": f"*Abuse Score:*\n{risk_data['breakdown'].get('abuse_confidence', 0)}",
            },
        ]

    message = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"GCP SOAR Alert: {action_status}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Project:*\n{project_id}"},
                    {"type": "mrkdwn", "text": f"*Instance:*\n`{instance_name}`"},
                    {"type": "mrkdwn", "text": f"*Threat:*\n{category}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                ]
                + score_fields,
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Finding ID:* {finding_id} | *Status:* {'Auto-Remediated' if approved else 'Awaiting Human Approval'}",  # noqa: E501
                    }
                ],
            },
        ]
    }

    # If pending approval, add interactive buttons
    if not approved:
        message["blocks"].append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve Isolation"},
                        "style": "danger",
                        "value": f"approve_{finding_id}",
                        "action_id": "approve_action",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Ignore / False Positive"},
                        "value": f"ignore_{finding_id}",
                        "action_id": "ignore_action",
                    },
                ],
            }
        )

    req = urllib.request.Request(SLACK_WEBHOOK_URL, json.dumps(message).encode("utf-8"))
    req.add_header("Content-Type", "application/json")
    try:
        urllib.request.urlopen(req)  # nosec B310
        logger.info("Sent Slack alert successfully.", extra={"json_fields": {"action": "SLACK_ALERT_SENT"}})
    except Exception as e:
        logger.error(f"Failed to send Slack alert: {str(e)}")

    # Kick off Jira Integration to generate an ITIL incident ticket
    try:
        from src.integrations.jira import create_jira_issue

        action_str = "✅ Remediated" if approved else "⏳ Pending Approval"
        desc = f"{category} on {instance_name}. {action_str}\nRisk Score: {risk_data.get('risk_score') if risk_data else 'N/A'}"  # noqa: E501
        create_jira_issue(instance_name, category, severity, desc)
    except Exception as e:
        logger.error(f"Failed to invoke Jira integration: {e}")


def isolate_instance(project_id, zone, instance_name):
    logger.info(f"Isolating {instance_name} by applying network tag: {ISOLATION_TAG}")
    client = get_compute_client()
    instance = client.get(project=project_id, zone=zone, instance=instance_name)
    tags = instance.tags

    tags.items = [ISOLATION_TAG]  # Overwrite tags

    operation = client.set_tags(project=project_id, zone=zone, instance=instance_name, tags_resource=tags)
    operation.result()  # Wait for completion


def detach_service_account(project_id, zone, instance_name):
    logger.info(f"Detaching Service Accounts from {instance_name}")
    client = get_compute_client()
    _instance = client.get(project=project_id, zone=zone, instance=instance_name)  # noqa: F841
    _operation = client.set_service_account(
        project=project_id,
        zone=zone,
        instance=instance_name,
        instances_set_service_account_request_resource=compute_v1.InstancesSetServiceAccountRequest(
            email="", scopes=[]
        ),
    )
    _operation.result()


def block_project_ssh_keys(project_id, zone, instance_name):
    logger.info(f"Blocking project-wide SSH keys for {instance_name} to prevent backdoor access")

    # Needs to get the instance fingerprint first to update metadata
    client = get_compute_client()
    instance = client.get(project=project_id, zone=zone, instance=instance_name)
    metadata = instance.metadata

    # Find existing items and update or append
    items = metadata.items if metadata.items else []

    key_exists = False
    for item in items:
        if item.key == "block-project-ssh-keys":
            item.value = "TRUE"
            key_exists = True
            break

    if not key_exists:
        items.append(compute_v1.Items(key="block-project-ssh-keys", value="TRUE"))

    metadata.items = items

    operation = client.set_metadata(project=project_id, zone=zone, instance=instance_name, metadata_resource=metadata)
    # Don't strictly need to wait but recommended for security configs
    operation.result()


def take_snapshot(project_id, zone, instance_name, threat_category):
    logger.info(f"Taking snapshot of boot disk for {instance_name}")
    client = get_compute_client()
    instance = client.get(project=project_id, zone=zone, instance=instance_name)

    # Find boot disk
    boot_disk_url = next((d.source for d in instance.disks if d.boot), None)
    if not boot_disk_url:
        logger.warning(f"No boot disk found for {instance_name}")
        return

    disk_name = boot_disk_url.split("/")[-1]
    timestamp_slug = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    snapshot_name = f"forensic-snapshot-{instance_name}-{timestamp_slug}"

    snapshot_resource = compute_v1.Snapshot(
        name=snapshot_name,
        description=f"Forensic snapshot driven by SOAR for threat: {threat_category}",
        labels={
            "purpose": "incident-response",
            "threat": threat_category.lower().replace(" ", "-"),
            "source-instance": instance_name,
        },
    )

    _ = get_disks_client().create_snapshot(
        project=project_id, zone=zone, disk=disk_name, snapshot_resource=snapshot_resource
    )
    # Note: Snapshots take time, we won't wait for result() in a cloud function.
    logger.info(f"Snapshot operation initiated: {snapshot_name}")


def stop_instance(project_id, zone, instance_name):
    logger.info(f"Stopping instance {instance_name}")
    _ = get_compute_client().stop(project=project_id, zone=zone, instance=instance_name)
    # Don't strictly need to wait for result.
