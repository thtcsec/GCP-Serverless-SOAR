# Enterprise SOAR GCP Security Module
# Cross-project security architecture with SA impersonation

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
# Central SOAR Service Account
# ==========================================
resource "google_service_account" "soar_central_sa" {
  account_id   = "${var.environment}-soar-central-sa"
  display_name = "SOAR Central Execution Service Account"
  description  = "Central SOAR service account with cross-project incident response capabilities"
}

# ==========================================
# Central SOAR SA — Project-Level Permissions
# ==========================================

# Compute — isolate instances, manage firewall, snapshots
resource "google_project_iam_member" "soar_compute_admin" {
  project = var.project_id
  role    = "roles/compute.instanceAdmin.v1"
  member  = "serviceAccount:${google_service_account.soar_central_sa.email}"
}

resource "google_project_iam_member" "soar_compute_security" {
  project = var.project_id
  role    = "roles/compute.securityAdmin"
  member  = "serviceAccount:${google_service_account.soar_central_sa.email}"
}

resource "google_project_iam_member" "soar_storage_admin" {
  project = var.project_id
  role    = "roles/compute.storageAdmin"
  member  = "serviceAccount:${google_service_account.soar_central_sa.email}"
}

# IAM — manage service account keys, role bindings
resource "google_project_iam_member" "soar_sa_admin" {
  project = var.project_id
  role    = "roles/iam.serviceAccountAdmin"
  member  = "serviceAccount:${google_service_account.soar_central_sa.email}"
}

resource "google_project_iam_member" "soar_project_iam" {
  project = var.project_id
  role    = "roles/resourcemanager.projectIamAdmin"
  member  = "serviceAccount:${google_service_account.soar_central_sa.email}"
}

# Cloud Functions — invoke SOAR functions
resource "google_project_iam_member" "soar_functions_invoker" {
  project = var.project_id
  role    = "roles/cloudfunctions.invoker"
  member  = "serviceAccount:${google_service_account.soar_central_sa.email}"
}

# Workflows — execute incident response workflows
resource "google_project_iam_member" "soar_workflow_invoker" {
  project = var.project_id
  role    = "roles/workflows.invoker"
  member  = "serviceAccount:${google_service_account.soar_central_sa.email}"
}

# Pub/Sub — publish/consume security events
resource "google_project_iam_member" "soar_pubsub_editor" {
  project = var.project_id
  role    = "roles/pubsub.editor"
  member  = "serviceAccount:${google_service_account.soar_central_sa.email}"
}

# Cloud Run — invoke container workers
resource "google_project_iam_member" "soar_run_invoker" {
  project = var.project_id
  role    = "roles/run.invoker"
  member  = "serviceAccount:${google_service_account.soar_central_sa.email}"
}

# Secret Manager — read integration credentials
resource "google_project_iam_member" "soar_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.soar_central_sa.email}"
}

# Logging — write structured logs
resource "google_project_iam_member" "soar_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.soar_central_sa.email}"
}

# ==========================================
# Cross-Project Responder Service Account
# ==========================================
resource "google_service_account" "soar_cross_project_sa" {
  count        = var.enable_cross_project_access ? 1 : 0
  account_id   = "${var.environment}-soar-cross-project"
  display_name = "SOAR Cross-Project Responder"
  description  = "Service account for cross-project incident response via SA impersonation"
}

# Allow central SA to impersonate the cross-project SA
resource "google_service_account_iam_member" "cross_project_impersonation" {
  count              = var.enable_cross_project_access ? 1 : 0
  service_account_id = google_service_account.soar_cross_project_sa[0].name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.soar_central_sa.email}"
}

# ==========================================
# Cross-Project IAM Bindings
# Grant the cross-project SA permissions on target projects
# ==========================================
resource "google_project_iam_member" "target_compute_admin" {
  for_each = var.enable_cross_project_access ? toset(var.target_project_ids) : toset([])

  project = each.value
  role    = "roles/compute.instanceAdmin.v1"
  member  = "serviceAccount:${google_service_account.soar_cross_project_sa[0].email}"
}

resource "google_project_iam_member" "target_compute_security" {
  for_each = var.enable_cross_project_access ? toset(var.target_project_ids) : toset([])

  project = each.value
  role    = "roles/compute.securityAdmin"
  member  = "serviceAccount:${google_service_account.soar_cross_project_sa[0].email}"
}

resource "google_project_iam_member" "target_sa_admin" {
  for_each = var.enable_cross_project_access ? toset(var.target_project_ids) : toset([])

  project = each.value
  role    = "roles/iam.serviceAccountAdmin"
  member  = "serviceAccount:${google_service_account.soar_cross_project_sa[0].email}"
}

resource "google_project_iam_member" "target_storage_admin" {
  for_each = var.enable_cross_project_access ? toset(var.target_project_ids) : toset([])

  project = each.value
  role    = "roles/storage.admin"
  member  = "serviceAccount:${google_service_account.soar_cross_project_sa[0].email}"
}

resource "google_project_iam_member" "target_project_iam" {
  for_each = var.enable_cross_project_access ? toset(var.target_project_ids) : toset([])

  project = each.value
  role    = "roles/resourcemanager.projectIamAdmin"
  member  = "serviceAccount:${google_service_account.soar_cross_project_sa[0].email}"
}

# ==========================================
# Centralized Logging Bucket
# ==========================================
resource "google_storage_bucket" "central_logs" {
  name          = "${var.project_id}-soar-central-logs-${var.environment}"
  location      = var.region
  storage_class = "STANDARD"

  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 365
    }
    action {
      type = "Delete"
    }
  }

  labels = merge(
    var.labels,
    {
      environment = var.environment
      purpose     = "centralized-logging"
    }
  )
}

# ==========================================
# Log Sink — route SOAR-related audit logs to bucket
# ==========================================
resource "google_logging_project_sink" "soar_audit_sink" {
  name        = "${var.environment}-soar-audit-log-sink"
  destination = "storage.googleapis.com/${google_storage_bucket.central_logs.name}"

  filter = <<-EOT
    resource.type="cloud_function" OR
    resource.type="cloud_run_revision" OR
    resource.type="workflows.googleapis.com/Workflow" OR
    protoPayload.serviceName="compute.googleapis.com" OR
    protoPayload.serviceName="iam.googleapis.com"
  EOT

  unique_writer_identity = true
}

# Grant the log sink writer access to the bucket
resource "google_storage_bucket_iam_member" "sink_writer" {
  bucket = google_storage_bucket.central_logs.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.soar_audit_sink.writer_identity
}

# ==========================================
# Event Threat Detection (ETD) via SCC
# ETD is part of SCC Premium. We enable the required API
# and create a notification config to route ETD findings to Pub/Sub.
# ==========================================

# Enable Security Command Center API
resource "google_project_service" "securitycenter_api" {
  project = var.project_id
  service = "securitycenter.googleapis.com"

  disable_dependent_services = false
  disable_on_destroy         = false
}

# Enable Event Threat Detection API
resource "google_project_service" "etd_api" {
  project = var.project_id
  service = "eventarc.googleapis.com"

  disable_dependent_services = false
  disable_on_destroy         = false
}

# Pub/Sub topic for ETD findings
resource "google_pubsub_topic" "etd_findings" {
  name    = "${var.environment}-soar-etd-findings"
  project = var.project_id

  labels = merge(
    var.labels,
    {
      environment = var.environment
      purpose     = "etd-findings"
    }
  )
}

# SCC Notification Config — routes ETD findings to Pub/Sub
# NOTE: Requires Organization-level SCC or project-level SCC Premium
resource "google_scc_project_notification_config" "etd_notifications" {
  config_id    = "${var.environment}-etd-findings"
  project      = var.project_id
  description  = "Route Event Threat Detection findings to Pub/Sub"
  pubsub_topic = google_pubsub_topic.etd_findings.id

  streaming_config {
    filter = "category=\"MALWARE\" OR category=\"CRYPTO_MINING\" OR category=\"BRUTE_FORCE\" OR category=\"PERSISTENCE\" OR category=\"INITIAL_ACCESS\" OR category=\"DEFENSE_EVASION\""
  }

  depends_on = [google_project_service.securitycenter_api]
}

# Grant Cloud Monitoring metrics writer role to SOAR SA
resource "google_project_iam_member" "soar_monitoring_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.soar_central_sa.email}"
}

# Grant Cloud Trace agent role to SOAR SA
resource "google_project_iam_member" "soar_trace_agent" {
  project = var.project_id
  role    = "roles/cloudtrace.agent"
  member  = "serviceAccount:${google_service_account.soar_central_sa.email}"
}
