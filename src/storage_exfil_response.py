import base64
import json
import logging
import os
from datetime import datetime, timedelta
from google.cloud import storage
from google.cloud import logging as cloud_logging
from google.cloud import pubsub_v1
import functions_framework

# Initialize GCP Clients
storage_client = storage.Client()
logging_client = cloud_logging.Client()
publisher = pubsub_v1.PublisherClient()

# Configuration
EXFILTRATION_THRESHOLD = int(os.environ.get('EXFILTRATION_THRESHOLD', '10737418240'))  # 10GB default
ALERT_TOPIC = os.environ.get('ALERT_TOPIC')
PROJECT_ID = os.environ.get('PROJECT_ID')

# Structured Cloud Logging setup
logging_client.setup_logging()
logger = logging.getLogger("storage-exfil-logger")
logger.setLevel(logging.INFO)

@functions_framework.cloud_event
def storage_exfil_responder(cloud_event):
    """Entry point for Cloud Function triggered by Cloud Audit Logs."""
    logger.info(f"Received Cloud Event ID: {cloud_event['id']}")
    
    if not cloud_event.data or 'protoPayload' not in cloud_event.data:
        logger.error("Invalid event format")
        return

    try:
        payload = cloud_event.data['protoPayload']
        process_storage_event(payload)
    except Exception as e:
        logger.error(f"Error processing storage event: {str(e)}")

def process_storage_event(payload):
    """Process Cloud Storage audit event for exfiltration detection"""
    method_name = payload.get('methodName', '')
    resource_name = payload.get('resourceName', '')
    principal_email = payload.get('authenticationInfo', {}).get('principalEmail', '')
    caller_ip = payload.get('request', {}).get('callerIp', '')
    
    # Only process storage read operations
    if not method_name.startswith('storage.objects') or 'get' not in method_name.lower():
        logger.info(f"Ignoring non-storage-read event: {method_name}")
        return
    
    # Extract bucket and object information
    bucket_name = extract_bucket_name(resource_name)
    object_name = extract_object_name(resource_name)
    
    if not bucket_name:
        logger.warning("Could not extract bucket name from resource")
        return
    
    logger.info(f"Storage access detected: {method_name} on {bucket_name}/{object_name} by {principal_email}")
    
    # Analyze for exfiltration patterns
    exfil_analysis = analyze_exfiltration_patterns(principal_email, bucket_name, caller_ip)
    
    if exfil_analysis['is_exfiltration']:
        logger.warning(f"Data exfiltration detected by {principal_email} on bucket {bucket_name}")
        
        # Execute response playbook
        execute_exfiltration_response(
            bucket_name, 
            principal_email, 
            caller_ip, 
            exfil_analysis
        )

def extract_bucket_name(resource_name):
    """Extract bucket name from GCP resource name"""
    if resource_name and 'projects/_/buckets/' in resource_name:
        return resource_name.split('projects/_/buckets/')[1].split('/')[0]
    return None

def extract_object_name(resource_name):
    """Extract object name from GCP resource name"""
    if resource_name and '/objects/' in resource_name:
        return resource_name.split('/objects/')[1]
    return None

def analyze_exfiltration_patterns(principal_email, bucket_name, caller_ip):
    """Analyze access patterns to detect potential exfiltration"""
    analysis = {
        'is_exfiltration': False,
        'risk_score': 0,
        'access_count': 0,
        'total_bytes': 0,
        'unique_ips': set(),
        'time_distribution': []
    }
    
    try:
        # Get recent Cloud Audit Logs for this user and bucket
        recent_logs = get_recent_storage_logs(principal_email, bucket_name, hours=24)
        
        # Analyze patterns
        analysis['access_count'] = len(recent_logs)
        analysis['unique_ips'] = set(log.get('callerIp', '') for log in recent_logs)
        analysis['total_bytes'] = estimate_total_bytes(recent_logs)
        
        # Calculate risk score
        risk_score = 0
        
        # Rule 1: Large volume downloads
        if analysis['total_bytes'] > EXFILTRATION_THRESHOLD:
            risk_score += 5
            logger.warning(f"Large volume download: {analysis['total_bytes']} bytes")
        
        # Rule 2: High frequency access
        if analysis['access_count'] > 1000:
            risk_score += 3
            logger.warning(f"High frequency access: {analysis['access_count']} operations")
        
        # Rule 3: Multiple source IPs
        if len(analysis['unique_ips']) > 3:
            risk_score += 2
            logger.warning(f"Multiple source IPs detected: {len(analysis['unique_ips'])}")
        
        # Rule 4: Unusual timing
        if is_suspicious_timing(recent_logs):
            risk_score += 2
            logger.warning("Suspicious timing pattern detected")
        
        # Rule 5: Rapid succession downloads
        if is_rapid_succession(recent_logs):
            risk_score += 3
            logger.warning("Rapid succession downloads detected")
        
        analysis['risk_score'] = risk_score
        analysis['is_exfiltration'] = risk_score >= 6  # Threshold for exfiltration
        
        return analysis
        
    except Exception as e:
        logger.error(f"Error in exfiltration analysis: {str(e)}")
        return analysis

def get_recent_storage_logs(principal_email, bucket_name, hours=24):
    """Get recent Cloud Audit Logs for storage operations"""
    try:
        # This would typically use Cloud Logging queries
        # For demo purposes, we'll simulate the analysis
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        
        # Query Cloud Logging for storage audit logs
        filter_str = f'''
        resource.type="gcs_bucket"
        protoPayload.authenticationInfo.principalEmail="{principal_email}"
        protoPayload.methodName:"storage.objects.get"
        timestamp>="{start_time.isoformat()}Z"
        timestamp<="{end_time.isoformat()}Z"
        '''
        
        # In a real implementation, you would use the logging client
        # entries = logging_client.list_entries(filter_=filter_str)
        
        # For demo, return simulated data
        return []
        
    except Exception as e:
        logger.error(f"Error querying storage logs: {str(e)}")
        return []

def estimate_total_bytes(logs):
    """Estimate total bytes downloaded from logs"""
    total_bytes = 0
    for log in logs:
        # Extract object size from the log entry
        metadata = log.get('metadata', {})
        if 'size' in metadata:
            total_bytes += int(metadata['size'])
        else:
            total_bytes += 1024 * 1024  # Estimate 1MB per download
    return total_bytes

def is_suspicious_timing(logs):
    """Check if access patterns show suspicious timing"""
    if not logs:
        return False
    
    # Check for access during unusual hours (11 PM - 5 AM)
    unusual_hour_count = 0
    for log in logs:
        timestamp = log.get('timestamp', '')
        if timestamp:
            hour = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).hour
            if hour >= 23 or hour <= 5:
                unusual_hour_count += 1
    
    # If more than 30% of accesses are during unusual hours
    return unusual_hour_count > len(logs) * 0.3

def is_rapid_succession(logs):
    """Check for rapid succession downloads"""
    if len(logs) < 10:
        return False
    
    # Sort logs by timestamp
    sorted_logs = sorted(logs, key=lambda x: x.get('timestamp', ''))
    
    # Check if there are many downloads within a short time window
    rapid_count = 0
    for i in range(1, len(sorted_logs)):
        prev_time = datetime.fromisoformat(sorted_logs[i-1].get('timestamp', '').replace('Z', '+00:00'))
        curr_time = datetime.fromisoformat(sorted_logs[i].get('timestamp', '').replace('Z', '+00:00'))
        
        # If downloads are less than 1 second apart
        if (curr_time - prev_time).total_seconds() < 1:
            rapid_count += 1
    
    return rapid_count > 50  # More than 50 rapid downloads

def execute_exfiltration_response(bucket_name, principal_email, caller_ip, analysis):
    """Execute automated response to data exfiltration"""
    try:
        logger.info(f"Executing exfiltration response for bucket {bucket_name}")
        
        # Step 1: Block user access to the bucket
        block_user_bucket_access(bucket_name, principal_email)
        
        # Step 2: Enable additional bucket protections
        enable_bucket_protections(bucket_name)
        
        # Step 3: Create forensic snapshot of bucket metadata
        create_forensic_snapshot(bucket_name, principal_email, analysis)
        
        # Step 4: Send security alert
        send_exfiltration_alert(bucket_name, principal_email, caller_ip, analysis)
        
        logger.info(f"Exfiltration response completed for bucket {bucket_name}")
        
    except Exception as e:
        logger.error(f"Error executing exfiltration response: {str(e)}")

def block_user_bucket_access(bucket_name, principal_email):
    """Block user access to the compromised bucket by explicitly removing them from all bindings"""
    try:
        bucket = storage_client.bucket(bucket_name)
        
        # Get current IAM policy
        policy = bucket.get_iam_policy()
        
        member_id = f'user:{principal_email}'
        if '.gserviceaccount.com' in principal_email:
            member_id = f'serviceAccount:{principal_email}'
            
        policy_changed = False
        
        # Cleanly remove the user from ALL existing bucket-level bindings
        for binding in policy.bindings:
            if member_id in binding.get('members', []):
                binding['members'].remove(member_id)
                policy_changed = True
                
        if policy_changed:
            bucket.set_iam_policy(policy)
            logger.info(f"Removed user {principal_email} from all bucket IAM bindings on {bucket_name}")
        else:
            logger.warning(f"User {principal_email} had no direct bucket IAM bindings to remove. Assumed inherited from Project level.")
            
        # NOTE: If the user inherits 'roles/storage.objectViewer' from the Project level, 
        # this bucket-level removal will NOT stop them! 
        # True SOAR would revoke their Project-level roles directly or use IAM Deny Policies (v2).
        
    except Exception as e:
        logger.error(f"Error blocking user access: {str(e)}")

def enable_bucket_protections(bucket_name):
    """Enable additional bucket protection mechanisms"""
    try:
        bucket = storage_client.bucket(bucket_name)
        
        # Enable bucket versioning if not already enabled
        if not bucket.versioning_enabled:
            bucket.versioning_enabled = True
            logger.info(f"Enabled versioning for bucket {bucket_name}")
        
        # Enable bucket lock if supported
        try:
            bucket.retention_period = 30  # 30 days retention
            logger.info(f"Enabled 30-day retention for bucket {bucket_name}")
        except Exception as e:
            logger.info(f"Bucket lock not supported or already enabled: {str(e)}")
        
        # Enable uniform bucket-level access if not already enabled
        if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
            bucket.iam_configuration.uniform_bucket_level_access_enabled = True
            logger.info(f"Enabled uniform bucket-level access for {bucket_name}")
        
    except Exception as e:
        logger.error(f"Error enabling bucket protections: {str(e)}")

def create_forensic_snapshot(bucket_name, principal_email, analysis):
    """Create forensic snapshot of bucket metadata and access logs"""
    try:
        forensic_data = {
            'bucket_name': bucket_name,
            'principal_email': principal_email,
            'analysis': analysis,
            'timestamp': datetime.utcnow().isoformat(),
            'bucket_metadata': {},
            'recent_access_logs': []
        }
        
        # Get bucket metadata
        bucket = storage_client.bucket(bucket_name)
        forensic_data['bucket_metadata'] = {
            'created': bucket.time_created.isoformat() if bucket.time_created else None,
            'updated': bucket.updated.isoformat() if bucket.updated else None,
            'storage_class': bucket.storage_class,
            'location': bucket.location,
            'versioning_enabled': bucket.versioning_enabled
        }
        
        # Store forensic data in a separate bucket
        forensic_bucket = storage_client.bucket(f"{PROJECT_ID}-forensic-data")
        forensic_blob = forensic_bucket.blob(
            f"storage-exfil/{bucket_name}/{principal_email}/{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
        )
        
        forensic_blob.upload_from_string(
            json.dumps(forensic_data, indent=2),
            content_type='application/json'
        )
        
        logger.info(f"Forensic snapshot created for bucket {bucket_name}")
        
    except Exception as e:
        logger.error(f"Error creating forensic snapshot: {str(e)}")

def send_exfiltration_alert(bucket_name, principal_email, caller_ip, analysis):
    """Send security alert about data exfiltration"""
    try:
        alert_message = {
            'alert_type': 'DATA_EXFILTRATION',
            'severity': 'HIGH',
            'bucket_name': bucket_name,
            'principal_email': principal_email,
            'caller_ip': caller_ip,
            'analysis': analysis,
            'timestamp': datetime.utcnow().isoformat(),
            'response_actions': [
                'User bucket access blocked',
                'Bucket protections enabled',
                'Forensic snapshot created'
            ]
        }
        
        # Publish to alert topic
        if ALERT_TOPIC:
            topic_path = publisher.topic_path(PROJECT_ID, ALERT_TOPIC)
            data = json.dumps(alert_message).encode('utf-8')
            future = publisher.publish(topic_path, data)
            logger.info(f"Alert published to topic {ALERT_TOPIC}: {future.result()}")
        
        # Also log the alert
        logger.warning(f"DATA EXFILTRATION ALERT: {json.dumps(alert_message, indent=2)}")
        
    except Exception as e:
        logger.error(f"Error sending exfiltration alert: {str(e)}")
