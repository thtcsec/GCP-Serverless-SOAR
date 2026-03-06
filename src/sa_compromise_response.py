import base64
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from google.cloud import iam_admin_v1
from google.cloud import logging as cloud_logging
from google.cloud import pubsub_v1
import functions_framework

# Initialize GCP Clients
iam_client = iam_admin_v1.IAMClient()
logging_client = cloud_logging.Client()
publisher = pubsub_v1.PublisherClient()

PROJECT_ID = os.environ.get('PROJECT_ID')
ALERT_TOPIC = os.environ.get('ALERT_TOPIC')

logging_client.setup_logging()
logger = logging.getLogger("sa-compromise-logger")
logger.setLevel(logging.INFO)

@functions_framework.cloud_event
def sa_compromise_responder(cloud_event):
    """Entry point for Cloud Function triggered by IAM audit logs."""
    try:
        payload = cloud_event.data['protoPayload']
        process_sa_event(payload)
    except Exception as e:
        logger.error(f"Error processing SA event: {str(e)}")

def process_sa_event(payload):
    """Process service account audit event for compromise detection"""
    method_name = payload.get('methodName', '')
    resource_name = payload.get('resourceName', '')
    principal_email = payload.get('authenticationInfo', {}).get('principalEmail', '')
    
    if not method_name.startswith('iam.serviceAccounts'):
        return
    
    sa_email = extract_sa_email(resource_name)
    if not sa_email:
        return
    
    risk_score = calculate_sa_risk_score(payload)
    
    if risk_score >= 7:
        logger.warning(f"Service account compromise detected: {sa_email}")
        execute_sa_response(sa_email, principal_email, risk_score, payload)

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

def execute_sa_response(sa_email, principal_email, risk_score, payload):
    """Execute automated response to SA compromise"""
    try:
        # Disable SA keys
        disable_sa_keys(sa_email)
        
        # Remove SA from critical roles
        remove_critical_roles(sa_email)
        
        # Send alert
        send_sa_alert(sa_email, principal_email, risk_score, payload)
        
    except Exception as e:
        logger.error(f"Error executing SA response: {str(e)}")

def disable_sa_keys(sa_email):
    """Disable all service account keys"""
    try:
        sa_resource = f"projects/{PROJECT_ID}/serviceAccounts/{sa_email}"
        
        # List all keys
        keys = iam_client.list_service_account_keys(name=sa_resource)
        
        for key in keys.keys:
            if key.key_type == iam_admin_v1.ServiceAccountKey.Type.USER_MANAGED:
                # Disable the key
                iam_client.disable_service_account_key(name=key.name)
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

def send_sa_alert(sa_email, principal_email, risk_score, payload):
    """Send security alert about SA compromise"""
    try:
        alert = {
            'alert_type': 'SERVICE_ACCOUNT_COMPROMISE',
            'severity': 'HIGH',
            'service_account': sa_email,
            'principal_email': principal_email,
            'risk_score': risk_score,
            'method_name': payload.get('methodName'),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'actions_taken': ['SA keys disabled', 'Critical roles removed']
        }
        
        if ALERT_TOPIC:
            topic_path = publisher.topic_path(PROJECT_ID, ALERT_TOPIC)
            data = json.dumps(alert).encode('utf-8')
            publisher.publish(topic_path, data)
        
        logger.warning(f"SA COMPROMISE ALERT: {json.dumps(alert)}")
        
    except Exception as e:
        logger.error(f"Error sending SA alert: {str(e)}")
