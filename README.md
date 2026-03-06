# 🚀 GCP Serverless Security Orchestration, Automation, and Response (SOAR)

![GCP](https://img.shields.io/badge/GoogleCloud-%234285F4.svg?style=for-the-badge&logo=google-cloud&logoColor=white) 
![Terraform](https://img.shields.io/badge/terraform-%235835CC.svg?style=for-the-badge&logo=terraform&logoColor=white) 
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Serverless](https://img.shields.io/badge/serverless-%23FD5750.svg?style=for-the-badge&logo=serverless&logoColor=white)

Automated security incident response platform that detects threats using Security Command Center and automatically isolates compromised resources while preserving forensic evidence.

## 🏗️ Architecture Overview

### System Architecture
```
Threat Detection → Event Router → Message Queue → Workflow Engine → Workers
     ↓                    ↓              ↓              ↓           ↓
GuardDuty/SCC → EventBridge/Eventarc → SQS/PubSub → Step Functions/Cloud Workflows → Container Workers
```

### GCP Architecture Flow
```mermaid
flowchart TD
    subgraph "Detection Layer"
        A[Security Command Center] --> D[Eventarc]
        B[Cloud Audit Logs] --> D
        C[Threat Detection] --> E[Pub/Sub]
    end
    
    subgraph "Processing Layer"
        D --> F[Cloud Workflows]
        E --> G[Cloud Run Workers]
    end
    
    subgraph "Response Layer"
        F --> H[Isolation Workers]
        F --> I[Forensics Workers]
        G --> J[Isolation Workers]
        G --> K[Forensics Workers]
    end
    
    subgraph "Notification Layer"
        H --> L[Slack/Jira/SIEM]
        I --> L
        J --> L
        K --> L
    end
```

### Workflow Process
1. **Detection:** SCC detects threats (severity >= 7.0)
2. **Event Routing:** Eventarc routes to Pub/Sub queue
3. **Workflow Engine:** Cloud Workflows orchestrates response
4. **Container Workers:** Cloud Run performs long-running operations
5. **Human Approval:** Manual approval for critical actions
6. **Integrations:** Slack, Jira, SIEM notifications

## �️ Architecture

### 🖼️ High-Level Architecture
![Architecture Diagram](images/gcp_soar.png)

### ⚙️ Logical Data Flow (Mermaid)
```mermaid
graph TD
  A[Attacker] -->|Compromises| B(GCE Target VM)
  A -->|Data Exfiltration| C[Cloud Storage]
  A -->|SA Compromise| D[Service Account]
  
  B -->|C&C / Crypto Mining| E{Security Command Center}
  C -->|Unusual Access| F{Cloud Audit Logs}
  D -->|Suspicious Activity| F
  
  E -->|High Severity Finding| G[Pub/Sub Topic]
  F -->|IAM/Storage Events| G
  
  G -->|Triggers Subscription| H((Cloud Function - GCE Response))
  G -->|Triggers Subscription| I((Cloud Function - Storage Response))
  G -->|Triggers Subscription| J((Cloud Function - SA Response))
  
  H -->|1. Change Network Tag| B
  H -->|2. Detach Service Account| B
  H -->|3. Block SSH Keys| B
  H -->|4. Take Snapshot| K[(Disk Snapshot)]
  H -->|5. Stop VM| B
  
  I -->|1. Block IAM Access| C
  I -->|2. Enable Versioning| C
  I -->|3. Set Retention| C
  I -->|4. Forensic Data| L[(Bucket Metadata)]
  
  J -->|1. Disable Keys| D
  J -->|2. Remove Roles| D
  J -->|3. Audit Logs| M[IAM Audit]
  J -->|4. Send Alert| N[Pub/Sub Alert]
  
  H -->|6. Send Alert| N
  I -->|5. Send Alert| N
  
  N -->|Security Team| O[Security Admin]
```

The workflow involves:
1. **Detection:** GCP Security Command Center detects anomalous behavior (e.g., Cryptocurrency mining).
2. **Event Routing:** SCC pushes the finding event to a Pub/Sub topic.
3. **Automation Logic:** A Python Cloud Function is triggered by the Pub/Sub message.
4. **Resolution (Response Playbook):** 
   - **Isolate:** Replaces the VM's network tags with an `isolated-vm` tag. A pre-configured VPC Firewall rule explicitly denies all ingress and egress to this tag.
   - **Revoke Service Account:** Detaches the IAM Service Account from the VM.
   - **Block SSH:** Sets the instance metadata `block-project-ssh-keys=TRUE` to prevent adversaries from persisting via GCP-wide SSH keys.
   - **Preserve:** Takes a Snapshot of the VM's primary disk with forensic metadata tags attached.
   - **Stop:** Stops the VM to halt local execution.

## 🛡️ Advanced Features

### Workflow Engine (Cloud Workflows)
- **Human approval** workflows for critical actions
- **Multi-step incident response** with retry logic
- **Parallel execution** for isolation and forensics
- **Error handling** and dead letter queue processing

### Message Queue Layer (Pub/Sub)
- **Buffer layer** prevents system overload during attacks
- **Dead Letter Topics** handles failed processing
- **Batch processing** for improved performance
- **Cross-project message routing**

### Container Workers (Cloud Run)
- **Long-running operations** (15+ minute forensic scans)
- **Full environment** access for comprehensive analysis
- **Scalable compute** with auto-scaling
- **Health monitoring** and graceful degradation

### Multi-Project Security
- **Centralized security project** with cross-project roles
- **SCC organization** configuration
- **Cross-project incident response** capabilities
- **Secure identity federation** with external IDs

### Integrations
- **Slack/Teams** for real-time notifications
- **Jira/ServiceNow** for ticket management
- **SIEM integration** (Chronicle, Splunk, Elastic)
- **Threat intelligence** feeds

## 🚀 Deployment

### Environment Structure
```
terraform/
├── modules/                    # Reusable modules
│   ├── workflows/             # Cloud Workflows
│   ├── queues/                # Pub/Sub and Eventarc
│   ├── containers/            # Cloud Run workers
│   └── security/              # Multi-project security
├── environments/               # Environment-specific configs
│   ├── dev/                   # Development environment
│   ├── staging/               # Staging environment
│   └── prod/                  # Production environment
└── existing/                  # Original basic setup
```

### Quick Deploy
```bash
# Deploy SOAR platform
cd gcp-serverless-soar
./scripts/deploy_gcp.sh prod

# Configure integrations
gcloud secrets create slack-webhook-url --replication-policy automatic
echo "YOUR_WEBHOOK_URL" | gcloud secrets versions add slack-webhook-url --data-file=-
```

## 📊 Security Coverage

| Threat Type | Detection | Response Time | Advanced Features |
|-------------|-----------|---------------|-------------------|
| GCE Compromise | SCC | < 30s | Workflow approval, container forensics |
| Storage Exfiltration | Audit Logs | < 60s | Cross-project response, SIEM integration |
| SA Compromise | Audit Logs | < 45s | Multi-project security, ticketing |
| DDoS Attacks | VPC Flow Logs | < 15s | Queue buffering, auto-scaling |

## 🔧 Configuration

### Variables
- `worker_desired_count`: Container worker instances (prod: 3, dev: 1)
- `approval_wait_time`: Human approval timeout (prod: 3600s, dev: 300s)
- `enable_multi_project`: Cross-project security (default: true)
- `enable_integrations`: Slack/Jira/SIEM (default: true)

### Integration Setup
```bash
# Slack integration
gcloud secrets create slack-webhook-url --replication-policy automatic
echo "WEBHOOK_URL" | gcloud secrets versions add slack-webhook-url --data-file=-

# Jira integration
gcloud secrets create jira-api-token --replication-policy automatic
echo "API_TOKEN" | gcloud secrets versions add jira-api-token --data-file=-

# SIEM integration
gcloud secrets create siem-api-key --replication-policy automatic
echo "API_KEY" | gcloud secrets versions add siem-api-key --data-file=-
```
