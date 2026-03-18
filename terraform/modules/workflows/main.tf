# Enterprise SOAR GCP Workflows Module
# Cloud Workflows for enterprise orchestration

terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

# ==========================================
# Cloud Workflows - Incident Response
# ==========================================
resource "google_workflows_workflow" "incident_response" {
  name        = "${var.environment}-soar-incident-response"
  location    = var.region
  description = "Enterprise SOAR incident response workflow"

  # Define the workflow in YAML format
  source_contents = <<-EOF
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Enterprise SOAR Incident Response Workflow
- init:
    call: http.post
    args:
      url: https://workflowexecutions.googleapis.com/v1/projects/$${sys.get_project_id()}/locations/$${sys.get_region()}/workflows/$${var.environment}-soar-detect-severity/execute
      body:
        finding: $${finding}
    result: severity_result

- detect_severity:
    call: http.post
    args:
      url: https://workflowexecutions.googleapis.com/v1/projects/$${sys.get_project_id()}/locations/$${sys.get_region()}/workflows/$${var.environment}-soar-detect-severity/execute
      body:
        finding: $${finding}
    result: severity_analysis

- isolate_instance:
    call: http.post
    args:
      url: https://workflowexecutions.googleapis.com/v1/projects/$${sys.get_project_id()}/locations/$${sys.get_region()}/workflows/$${var.environment}-soar-isolate-instance/execute
      body:
        instance_data: $${severity_analysis.instance_data}
        severity: $${severity_analysis.severity_level}
    result: isolation_result

- create_snapshot:
    call: http.post
    args:
      url: https://workflowexecutions.googleapis.com/v1/projects/$${sys.get_project_id()}/locations/$${sys.get_region()}/workflows/$${var.environment}-soar-create-snapshot/execute
      body:
        instance_data: $${severity_analysis.instance_data}
    result: snapshot_result

- human_approval:
    call: sys.sleep
    args:
      seconds: $${var.approval_wait_time}
    next: check_approval

- check_approval:
    switch:
      - condition: $${approval_status == "approved"}
        next: terminate_instance
      - condition: $${approval_status == "rejected"}
        next: manual_investigation
      - condition: $${approval_status == "timeout"}
        next: terminate_instance

- terminate_instance:
    call: http.post
    args:
      url: https://workflowexecutions.googleapis.com/v1/projects/$${sys.get_project_id()}/locations/$${sys.get_region()}/workflows/$${var.environment}-soar-terminate-instance/execute
      body:
        instance_data: $${severity_analysis.instance_data}
    result: termination_result

- manual_investigation:
    call: http.post
    args:
      url: https://workflowexecutions.googleapis.com/v1/projects/$${sys.get_project_id()}/locations/$${sys.get_region()}/workflows/$${var.environment}-soar-notify-team/execute
      body:
        message: "Manual investigation required for instance $${severity_analysis.instance_data.instance_name}"
    result: notification_result

- final_result:
    return:
      workflow_id: $${sys.get_workflow_id()}
      execution_id: $${sys.get_execution_id()}
      severity_analysis: $${severity_analysis}
      isolation_result: $${isolation_result}
      snapshot_result: $${snapshot_result}
      termination_result: $${termination_result}
      timestamp: $${sys.get_time()}
EOF

  service_account = google_service_account.workflow_sa.email

  labels = merge(
    var.labels,
    {
      environment = var.environment
      purpose     = "soar-workflow"
    }
  )
}

# ==========================================
# Individual Workflow Steps as separate workflows
# ==========================================

# Severity Detection Workflow
resource "google_workflows_workflow" "detect_severity" {
  name        = "${var.environment}-soar-detect-severity"
  location    = var.region
  description = "Detect severity of security findings"

  source_contents = <<-EOF
- analyze_finding:
    call: http.post
    args:
      url: https://workflowexecutions.googleapis.com/v1/projects/$${sys.get_project_id()}/locations/$${sys.get_region()}/workflows/$${var.environment}-soar-detect-severity/execute
      body:
        finding: $${finding}
    result: severity_result

- classify_severity:
    switch:
      - condition: $${severity_result.severity_score >= 8.0}
        assign:
          - severity_level: "CRITICAL"
          - priority: "P1"
          - requires_approval: true
      - condition: $${severity_result.severity_score >= 6.0}
        assign:
          - severity_level: "HIGH"
          - priority: "P2"
          - requires_approval: true
      - condition: $${severity_result.severity_score >= 4.0}
        assign:
          - severity_level: "MEDIUM"
          - priority: "P3"
          - requires_approval: false
      - default:
        assign:
          - severity_level: "LOW"
          - priority: "P4"
          - requires_approval: false

- return_result:
    return:
      severity_level: $${severity_level}
      priority: $${priority}
      requires_approval: $${requires_approval}
      severity_score: $${severity_result.severity_score}
      instance_data: $${severity_result.instance_data}
      analysis_timestamp: $${sys.get_time()}
EOF

  service_account = google_service_account.workflow_sa.email

  labels = merge(
    var.labels,
    {
      environment = var.environment
      purpose     = "severity-detection"
    }
  )
}

# Instance Isolation Workflow
resource "google_workflows_workflow" "isolate_instance" {
  name        = "${var.environment}-soar-isolate-instance"
  location    = var.region
  description = "Isolate compromised compute instances"

  source_contents = <<-EOF
- validate_instance:
    call: compute.instances.get
    args:
      project: $${sys.get_project_id()}
      zone: $${instance_data.zone}
      instance: $${instance_data.instance_name}
    result: instance_details

- apply_firewall_rules:
    call: compute.firewalls.patch
    args:
      project: $${sys.get_project_id()}
      firewall: $${var.isolation_firewall_name}
      body:
        denied:
          - ipProtocol: "TCP"
          - ipProtocol: "UDP"
          - ipProtocol: "ICMP"
        direction: "INGRESS"
        priority: 1
        targetTags:
          - "isolated-$${instance_data.instance_name}"
    result: firewall_result

- update_instance_tags:
    call: compute.instances.setTags
    args:
      project: $${sys.get_project_id()}
      zone: $${instance_data.zone}
      instance: $${instance_data.instance_name}
      tags:
        items:
          - fingerprint: $${instance_details.tags.fingerprint}
          - labels:
              isolation-status: "isolated"
              isolation-timestamp: "$${sys.get_time()}"
    result: tag_result

- verify_isolation:
    call: compute.instances.get
    args:
      project: $${sys.get_project_id()}
      zone: $${instance_data.zone}
      instance: $${instance_data.instance_name}
    result: verification_result

- return_result:
    return:
      instance_name: $${instance_data.instance_name}
      isolation_successful: true
      isolation_timestamp: $${sys.get_time()}
      firewall_rules_applied: $${firewall_result.name}
      verification_result: $${verification_result}
EOF

  service_account = google_service_account.workflow_sa.email

  labels = merge(
    var.labels,
    {
      environment = var.environment
      purpose     = "instance-isolation"
    }
  )
}

# Snapshot Creation Workflow
resource "google_workflows_workflow" "create_snapshot" {
  name        = "${var.environment}-soar-create-snapshot"
  location    = var.region
  description = "Create forensic snapshots of compute instances"

  source_contents = <<-EOF
- get_instance_details:
    call: compute.instances.get
    args:
      project: $${sys.get_project_id()}
      zone: $${instance_data.zone}
      instance: $${instance_data.instance_name}
    result: instance_details

- create_disk_snapshot:
    call: compute.disks.createSnapshot
    args:
      project: $${sys.get_project_id()}
      disk: $${instance_details.disks[0].source}
      body:
        name: "forensic-$${instance_data.instance_name}-$${sys.get_time()}"
        description: "Forensic snapshot for incident response"
        labels:
          purpose: "forensic-analysis"
          instance-name: "$${instance_data.instance_name}"
          created-by: "soar-workflow"
          environment: "$${var.environment}"
    result: snapshot_result

- wait_for_snapshot:
    call: compute.snapshots.get
    args:
      project: $${sys.get_project_id()}
      snapshot: $${snapshot_result.name}
    result: snapshot_status

- return_result:
    return:
      instance_name: $${instance_data.instance_name}
      snapshot_name: $${snapshot_result.name}
      snapshot_status: $${snapshot_status.status}
      creation_timestamp: $${sys.get_time()}
      disk_size_gb: $${instance_details.disks[0].diskSizeGb}
EOF

  service_account = google_service_account.workflow_sa.email

  labels = merge(
    var.labels,
    {
      environment = var.environment
      purpose     = "snapshot-creation"
    }
  )
}

# ==========================================
# Workflow Service Account
# ==========================================
resource "google_service_account" "workflow_sa" {
  account_id   = "${var.environment}-soar-workflow-sa"
  display_name = "SOAR Workflow Service Account"
  description  = "Service account for SOAR Cloud Workflows"

  labels = merge(
    var.labels,
    {
      environment = var.environment
      purpose     = "soar-workflows"
    }
  )
}

# ==========================================
# Workflow IAM Permissions
# ==========================================
resource "google_project_iam_member" "workflow_invoker" {
  project = var.project_id
  role    = "roles/workflows.invoker"
  member  = "serviceAccount:${google_service_account.workflow_sa.email}"
}

resource "google_project_iam_member" "workflow_editor" {
  project = var.project_id
  role    = "roles/workflows.editor"
  member  = "serviceAccount:${google_service_account.workflow_sa.email}"
}

resource "google_project_iam_member" "compute_viewer" {
  project = var.project_id
  role    = "roles/compute.viewer"
  member  = "serviceAccount:${google_service_account.workflow_sa.email}"
}

resource "google_project_iam_member" "compute_security_admin" {
  project = var.project_id
  role    = "roles/compute.securityAdmin"
  member  = "serviceAccount:${google_service_account.workflow_sa.email}"
}
