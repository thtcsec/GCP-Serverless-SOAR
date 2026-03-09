import base64
import json
import logging
import os
from datetime import datetime, timezone, timedelta, timezone
import src.integrations as integrations
try:
    from google.cloud import iam_admin_v1
except Exception:
    iam_admin_v1 = None  # type: ignore[assignment]
from google.cloud import logging as cloud_logging
try:
    from google.cloud import pubsub_v1  # type: ignore[attr-defined]
except Exception:
    pubsub_v1 = None  # type: ignore[assignment]
import functions_framework

iam_client = None
logging_client = None
publisher = None

PROJECT_ID = os.environ.get('PROJECT_ID')
ALERT_TOPIC = os.environ.get('ALERT_TOPIC')

logger = logging.getLogger("sa-compromise-logger")
logger.setLevel(logging.INFO)

def setup_logging():
    global logging_client
    if getattr(setup_logging, "configured", False):
        return
    try:
        logging_client = cloud_logging.Client()
        logging_client.setup_logging()
    except Exception:
        logging.basicConfig(level=logging.INFO)
    setup_logging.configured = True

def get_iam_client():
    global iam_client
    if iam_client is None:
        if iam_admin_v1 is None:
            raise ImportError("google.cloud.iam_admin_v1 is not available")
        iam_client = iam_admin_v1.IAMClient()
    return iam_client

def get_publisher():
    global publisher
    if publisher is None:
        if pubsub_v1 is None:
            raise ImportError("google.cloud.pubsub_v1 is not available")
        publisher = pubsub_v1.PublisherClient()
    return publisher

@functions_framework.cloud_event
def sa_compromise_responder(cloud_event):
    """Entry point for Cloud Function triggered by IAM audit logs."""
    setup_logging()
    try:
        payload = cloud_event.data['protoPayload']
        process_sa_event(payload)
    except Exception as e:
        logger.error(f"Error processing SA event: {str(e)}")

def process_sa_event(payload):
    """Process service account audit event for compromise detection"""
    setup_logging()
    method_name = payload.get('methodName', '')
    resource_name = payload.get('resourceName', '')
    principal_email = payload.get('authenticationInfo', {}).get('principalEmail', '')
    
    if not method_name.startswith('iam.serviceAccounts'):
        return
    
    sa_email = extract_sa_email(resource_name)
    if not sa_email:
        return
    
    risk_score = calculate_sa_risk_score(payload)
    caller_ip = payload.get('request', {}).get('callerIp', '')
    
    # --- THREAT INTEL ENRICHMENT & SCORING ---
    risk_data = {"risk_score": 0.0, "decision": "AUTO_ISOLATE"}
    intel_report = {}

    if caller_ip:
        logger.info(f"Enriching GCP SA finding with Intel for IP: {caller_ip}")
        intel_service = integrations.ThreatIntelService()
        intel_report = intel_service.get_ip_report(caller_ip)
        
        scoring_engine = integrations.ScoringEngine()
        # Scale SA risk_score (0-10) to engine expectations
        risk_data = scoring_engine.calculate_risk_score(intel_report, risk_score)
        
        logger.info(f"Scoring Result: {json.dumps(risk_data, default=str)}")
        
        if risk_data.get('decision') == "IGNORE":
            logger.info("Risk Score too low. Skipping remediation.")
            return

        if risk_data.get('decision') == "REQUIRE_APPROVAL":
            logger.info("Requires manual approval.")
            send_sa_alert(sa_email, principal_email, risk_data, payload, approved=False, intel_report=intel_report)
            return

    # Execute response (AUTO_ISOLATE)
    decision = risk_data.get('decision', 'AUTO_ISOLATE')
    logger.warning(f"Confirmed high-risk SA compromise: {sa_email} (Decision: {decision})")
    execute_sa_response(sa_email, principal_email, risk_data, payload, intel_report=intel_report)

def extract_sa_email(resource_name):
    """Extract service account email from resource name"""
    if resource_name and 'serviceAccounts/' in resource_name:
        return resource_name.split('serviceAccounts/')[1]
    return None

def calculate_sa_risk_score(payload):
    """Calculate risk score for service account activity"""
    score = 0
    method_name = payload.get('methodName', '')
    
    # High-risk operations
    high_risk_methods = [
        'CreateServiceAccountKey', 'SetIamPolicy', 'UndeleteServiceAccountKey'
    ]
    
    if method_name in high_risk_methods:
        score += 5
    
    # Check for unusual source
    if is_unusual_source(payload):
        score += 3
    
    # Check timing
    if is_suspicious_timing():
        score += 2
    
    return min(score, 10)

def is_unusual_source(payload):
    """Check if source is unusual for this operation"""
    caller_ip = payload.get('request', {}).get('callerIp', '')
    # Simple heuristic: check if it's not from known GCP services
    return not caller_ip.startswith(('compute.google', 'container.google'))

def is_suspicious_timing():
    """Check if current time is suspicious"""
    hour = datetime.now(timezone.utc).hour
    return hour >= 23 or hour <= 5

def execute_sa_response(sa_email, principal_email, risk_data, payload, intel_report=None):
    """Execute automated response to SA compromise"""
    try:
        # Disable SA keys
        disable_sa_keys(sa_email)
        
        # Remove SA from critical roles
        remove_critical_roles(sa_email)
        
        # Send alert
        send_sa_alert(sa_email, principal_email, risk_data, payload, approved=True, intel_report=intel_report)
        
    except Exception as e:
        logger.error(f"Error executing SA response: {str(e)}")

def disable_sa_keys(sa_email):
    """Disable all service account keys"""
    try:
        client = get_iam_client()
        sa_resource = f"projects/{PROJECT_ID}/serviceAccounts/{sa_email}"
        
        # List all keys
        keys = client.list_service_account_keys(name=sa_resource)
        
        for key in keys.keys:
            if key.key_type == iam_admin_v1.ServiceAccountKey.Type.USER_MANAGED:
                # Disable the key
                client.disable_service_account_key(name=key.name)
                logger.info(f"Disabled SA key: {key.name}")
                
    except Exception as e:
        logger.error(f"Error disabling SA keys: {str(e)}")

def remove_critical_roles(sa_email):
    """Remove service account from critical IAM roles at the project level"""
    try:
        critical_roles = [
            'roles/editor', 'roles/owner', 'roles/admin',
            'roles/storage.admin', 'roles/compute.admin'
        ]
        
        # Initialize Resource Manager Client for Project IAM bindings
        from google.cloud import resourcemanager_v3
        rm_client = resourcemanager_v3.ProjectsClient()
        project_name = f"projects/{PROJECT_ID}"
        
        # Get current project IAM policy
        policy = rm_client.get_iam_policy(request={"resource": project_name})
        
        member_to_remove = f"serviceAccount:{sa_email}"
        policy_changed = False
        
        # Filter out the compromised SA from critical roles
        for binding in policy.bindings:
            if binding.role in critical_roles:
                if member_to_remove in binding.members:
                    binding.members.remove(member_to_remove)
                    logger.info(f"Preparing to remove {binding.role} from {sa_email}")
                    policy_changed = True
                    
        # Apply the updated policy back to the project if changes were made
        if policy_changed:
            rm_client.set_iam_policy(request={
                "resource": project_name,
                "policy": policy
            })
            logger.info(f"Project IAM policy updated: critical roles removed for {sa_email}")
        else:
            logger.info(f"No critical project-level roles found for {sa_email}")
                
    except Exception as e:
        logger.error(f"Error removing critical roles: {str(e)}")

def send_sa_alert(sa_email, principal_email, risk_data, payload, approved=True, intel_report=None):
    """Send security alert about SA compromise"""
    try:
        action_status = "AUTOMATED RESPONSE EXECUTED" if approved else "PENDING APPROVAL"
        
        alert = {
            'alert_type': 'SERVICE_ACCOUNT_COMPROMISE',
            'severity': 'HIGH',
            'service_account': sa_email,
            'principal_email': principal_email,
            'risk_score': risk_data.get('risk_score') if risk_data else 'N/A',
            'decision': risk_data.get('decision') if risk_data else 'AUTO_ISOLATE',
            'method_name': payload.get('methodName'),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'actions_taken': ['SA keys disabled', 'Critical roles removed'] if approved else ['Detection Only'],
            'approved': approved,
            'intel_summary': {
                'vt_malicious': risk_data.get('breakdown', {}).get('vt_malicious') if risk_data else 0
            }
        }
        
        if ALERT_TOPIC:
            topic_path = get_publisher().topic_path(PROJECT_ID, ALERT_TOPIC)
            data = json.dumps(alert, default=str).encode('utf-8')
            get_publisher().publish(topic_path, data)
        
        logger.warning(f"SA COMPROMISE ALERT ({action_status}): {json.dumps(alert)}")
        
        # Optional Jira integration
        try:
            from src.integrations.jira import create_jira_issue
            desc = f"SA Compromise: {sa_email} by {principal_email}\nAction: {action_status}\nIntel: {json.dumps(intel_report, indent=2)}"
            create_jira_issue(sa_email, "SA_COMPROMISE", 9, desc)
        except Exception as e:
            logger.error(f"Failed to invoke Jira integration: {e}")
            
    except Exception as e:
        logger.error(f"Error sending SA alert: {str(e)}")
