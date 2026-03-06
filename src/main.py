import base64
import json
import logging
import urllib.request
import os
from datetime import datetime
from google.cloud import compute_v1
import functions_framework

# Initialize GCP Clients
compute_client = compute_v1.InstancesClient()
disks_client = compute_v1.DisksClient()
snapshots_client = compute_v1.SnapshotsClient()

ISOLATION_TAG = 'isolated-vm'
SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL')

# Structured Cloud Logging setup
client = google.cloud.logging.Client()
client.setup_logging()
logger = logging.getLogger("soar-ir-logger")
logger.setLevel(logging.INFO)

@functions_framework.cloud_event
def soar_responder(cloud_event):
    """Entry point for the Cloud Function triggered by Pub/Sub."""
    logger.info(f"Received Cloud Event ID: {cloud_event['id']}")
    
    if not cloud_event.data or 'message' not in cloud_event.data:
        logger.error("Invalid event format")
        return

    # Decode Pub/Sub message
    message_data = base64.b64decode(cloud_event.data['message']['data']).decode('utf-8')
    try:
        finding = json.loads(message_data)
        process_finding(finding)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse finding JSON: {str(e)}")


def process_finding(finding):
    severity = finding.get('severity', '')
    category = finding.get('category', '')
    resource_name = finding.get('resourceName', '') # Format: //compute.googleapis.com/projects/.../instances/instance-id
    
    logger.info(f"Processing SCC Finding - Category: {category}, Severity: {severity}, Resource: {resource_name}")

    if severity not in ['HIGH', 'CRITICAL']:
        logger.info(f"Ignoring finding with severity {severity}. Only HIGH or CRITICAL are processed.")
        return

    allowed_categories = ['Cryptocurrency mining', 'Backdoor', 'Malware']
    if not any(cat in category for cat in allowed_categories):
        logger.info(f"Ignoring category {category}. Not in target threat list.")
        return

    if not resource_name or "/instances/" not in resource_name:
        logger.warning("Resource is not a Compute Engine instance or is malformed.")
        return

    # Extract project, zone, instance from resource_name
    # Example format: //compute.googleapis.com/projects/my-project/zones/us-central1-a/instances/my-instance
    parts = resource_name.split('/')
    try:
        project_id = parts[4]
        zone = parts[6]
        instance_name = parts[8]
    except IndexError:
        logger.error(f"Failed to parse resource name: {resource_name}")
        return

    logger.info(f"Executing SOAR playbook on instance {instance_name} in {zone}", extra={
        "json_fields": {"action": "SOAR_TRIGGER", "instance": instance_name, "zone": zone, "threat": category}
    })

    try:
        isolate_instance(project_id, zone, instance_name)
        detach_service_account(project_id, zone, instance_name)
        take_snapshot(project_id, zone, instance_name, category)
        stop_instance(project_id, zone, instance_name)
        
        logger.info(f"SOAR Playbook completed successfully for {instance_name}", extra={
            "json_fields": {"action": "SOAR_COMPLETE", "instance": instance_name, "status": "success"}
        })
        
        send_slack_alert(project_id, zone, instance_name, category, severity)
        
    except Exception as e:
        logger.error(f"Failed to execute SOAR playbook: {str(e)}", extra={
            "json_fields": {"action": "SOAR_ERROR", "error": str(e)}
        })

def send_slack_alert(project_id, zone, instance_name, category, severity):
    if not SLACK_WEBHOOK_URL:
        logger.warning("SLACK_WEBHOOK_URL not configured. Skipping Slack alert.")
        return
        
    message = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🚨 GCP Security Incident Remediated 🚨",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Project:*\n{project_id}"},
                    {"type": "mrkdwn", "text": f"*Zone:*\n{zone}"},
                    {"type": "mrkdwn", "text": f"*Instance:*\n`{instance_name}`"},
                    {"type": "mrkdwn", "text": f"*Threat Category:*\n{category}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                    {"type": "mrkdwn", "text": f"*SOAR Status:*\n✅ Isolated, SA Detached, Snapshotted, Stopped."}
                ]
            }
        ]
    }
    
    req = urllib.request.Request(SLACK_WEBHOOK_URL, json.dumps(message).encode('utf-8'))
    req.add_header('Content-Type', 'application/json')
    try:
        urllib.request.urlopen(req)
        logger.info("Sent Slack alert successfully.", extra={"json_fields": {"action": "SLACK_ALERT_SENT"}})
    except Exception as e:
        logger.error(f"Failed to send Slack alert: {str(e)}")


def isolate_instance(project_id, zone, instance_name):
    logger.info(f"Isolating {instance_name} by applying network tag: {ISOLATION_TAG}")
    instance = compute_client.get(project=project_id, zone=zone, instance=instance_name)
    tags = instance.tags
    
    tags.items = [ISOLATION_TAG] # Overwrite tags
    
    operation = compute_client.set_tags(
        project=project_id,
        zone=zone,
        instance=instance_name,
        tags_resource=tags
    )
    operation.result() # Wait for completion


def detach_service_account(project_id, zone, instance_name):
    logger.info(f"Detaching Service Accounts from {instance_name}")
    instance = compute_client.get(project=project_id, zone=zone, instance=instance_name)
    
    # Pass empty service accounts list to detach
    operation = compute_client.set_service_account(
        project=project_id,
        zone=zone,
        instance=instance_name,
        instances_set_service_account_request_resource=compute_v1.InstancesSetServiceAccountRequest(
            email="",
            scopes=[]
        )
    )
    operation.result()


def take_snapshot(project_id, zone, instance_name, threat_category):
    logger.info(f"Taking snapshot of boot disk for {instance_name}")
    instance = compute_client.get(project=project_id, zone=zone, instance=instance_name)
    
    # Find boot disk
    boot_disk_url = next((d.source for d in instance.disks if d.boot), None)
    if not boot_disk_url:
        logger.warning(f"No boot disk found for {instance_name}")
        return

    disk_name = boot_disk_url.split('/')[-1]
    timestamp_slug = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    snapshot_name = f"forensic-snapshot-{instance_name}-{timestamp_slug}"

    snapshot_resource = compute_v1.Snapshot(
        name=snapshot_name,
        description=f"Forensic snapshot driven by SOAR for threat: {threat_category}",
        labels={
            "purpose": "incident-response",
            "threat": threat_category.lower().replace(" ", "-"),
            "source-instance": instance_name
        }
    )

    operation = disks_client.create_snapshot(
        project=project_id,
        zone=zone,
        disk=disk_name,
        snapshot_resource=snapshot_resource
    )
    # Note: Snapshots take time, we won't wait for result() in a cloud function.
    logger.info(f"Snapshot operation initiated: {snapshot_name}")


def stop_instance(project_id, zone, instance_name):
    logger.info(f"Stopping instance {instance_name}")
    operation = compute_client.stop(project=project_id, zone=zone, instance=instance_name)
    # Don't strictly need to wait for result.
