# Enterprise SOAR GCP Integrations Module
# Slack, Jira, and SIEM integrations via Cloud Functions + Secret Manager

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
# Integration Service Account
# ==========================================
resource "google_service_account" "integration_sa" {
  account_id   = "${var.environment}-soar-integrations"
  display_name = "SOAR Integrations Service Account"
  description  = "Service account for SOAR Slack/Jira/SIEM integration Cloud Functions"
}

# Secret Manager access — read webhook URLs, API tokens
resource "google_project_iam_member" "integration_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.integration_sa.email}"
}

# Logging
resource "google_project_iam_member" "integration_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.integration_sa.email}"
}

# ==========================================
# Source Code Archive
# ==========================================
data "archive_file" "integrations_zip" {
  type        = "zip"
  output_path = "${path.module}/integrations_source.zip"
  source_dir  = "${path.module}/../../src"
}

resource "google_storage_bucket" "integrations_source" {
  name                        = "${var.project_id}-soar-integrations-src-${var.environment}"
  location                    = var.region
  uniform_bucket_level_access = true

  labels = merge(var.labels, { purpose = "integrations-source" })
}

resource "google_storage_bucket_object" "integrations_archive" {
  name   = "integrations-${data.archive_file.integrations_zip.output_md5}.zip"
  bucket = google_storage_bucket.integrations_source.name
  source = data.archive_file.integrations_zip.output_path
}

# ==========================================
# Slack Notifier Cloud Function
# ==========================================
resource "google_cloudfunctions2_function" "slack_notifier" {
  count    = var.enable_slack_integration ? 1 : 0
  name     = "${var.environment}-soar-slack-notifier"
  location = var.region

  build_config {
    runtime     = "python312"
    entry_point = "slack_notify"
    source {
      storage_source {
        bucket = google_storage_bucket.integrations_source.name
        object = google_storage_bucket_object.integrations_archive.name
      }
    }
  }

  service_config {
    max_instance_count    = 5
    min_instance_count    = 0
    available_memory      = "256M"
    timeout_seconds       = 60
    service_account_email = google_service_account.integration_sa.email

    environment_variables = {
      PROJECT_ID  = var.project_id
      ENVIRONMENT = var.environment
      LOG_LEVEL   = "INFO"
    }
  }

  labels = merge(var.labels, { purpose = "slack-notifications" })
}

# ==========================================
# Jira Manager Cloud Function
# ==========================================
resource "google_cloudfunctions2_function" "jira_manager" {
  count    = var.enable_jira_integration ? 1 : 0
  name     = "${var.environment}-soar-jira-manager"
  location = var.region

  build_config {
    runtime     = "python312"
    entry_point = "jira_handler"
    source {
      storage_source {
        bucket = google_storage_bucket.integrations_source.name
        object = google_storage_bucket_object.integrations_archive.name
      }
    }
  }

  service_config {
    max_instance_count    = 5
    min_instance_count    = 0
    available_memory      = "256M"
    timeout_seconds       = 120
    service_account_email = google_service_account.integration_sa.email

    environment_variables = {
      PROJECT_ID  = var.project_id
      ENVIRONMENT = var.environment
      LOG_LEVEL   = "INFO"
    }
  }

  labels = merge(var.labels, { purpose = "jira-ticket-management" })
}

# ==========================================
# SIEM Forwarder Cloud Function
# ==========================================
resource "google_cloudfunctions2_function" "siem_forwarder" {
  count    = var.enable_siem_integration ? 1 : 0
  name     = "${var.environment}-soar-siem-forwarder"
  location = var.region

  build_config {
    runtime     = "python312"
    entry_point = "siem_forward"
    source {
      storage_source {
        bucket = google_storage_bucket.integrations_source.name
        object = google_storage_bucket_object.integrations_archive.name
      }
    }
  }

  service_config {
    max_instance_count    = 10
    min_instance_count    = 0
    available_memory      = "256M"
    timeout_seconds       = 120
    service_account_email = google_service_account.integration_sa.email

    environment_variables = {
      PROJECT_ID  = var.project_id
      ENVIRONMENT = var.environment
      LOG_LEVEL   = "INFO"
    }
  }

  labels = merge(var.labels, { purpose = "siem-data-forwarding" })
}

# ==========================================
# Eventarc Triggers — fire on SOAR workflow events
# ==========================================
resource "google_pubsub_topic" "integration_events" {
  name = "${var.environment}-soar-integration-events"

  labels = merge(var.labels, { purpose = "integration-events" })
}

# Push to Slack on all SOAR events
resource "google_pubsub_subscription" "slack_push" {
  count = var.enable_slack_integration ? 1 : 0
  name  = "${var.environment}-soar-slack-push"
  topic = google_pubsub_topic.integration_events.name

  push_config {
    push_endpoint = google_cloudfunctions2_function.slack_notifier[0].service_config[0].uri
    oidc_token {
      service_account_email = google_service_account.integration_sa.email
    }
  }

  ack_deadline = 60

  labels = merge(var.labels, { purpose = "slack-push" })
}

# Push to Jira on incident events
resource "google_pubsub_subscription" "jira_push" {
  count = var.enable_jira_integration ? 1 : 0
  name  = "${var.environment}-soar-jira-push"
  topic = google_pubsub_topic.integration_events.name

  push_config {
    push_endpoint = google_cloudfunctions2_function.jira_manager[0].service_config[0].uri
    oidc_token {
      service_account_email = google_service_account.integration_sa.email
    }
  }

  ack_deadline = 120

  labels = merge(var.labels, { purpose = "jira-push" })
}

# Push all events to SIEM
resource "google_pubsub_subscription" "siem_push" {
  count = var.enable_siem_integration ? 1 : 0
  name  = "${var.environment}-soar-siem-push"
  topic = google_pubsub_topic.integration_events.name

  push_config {
    push_endpoint = google_cloudfunctions2_function.siem_forwarder[0].service_config[0].uri
    oidc_token {
      service_account_email = google_service_account.integration_sa.email
    }
  }

  ack_deadline = 120

  labels = merge(var.labels, { purpose = "siem-push" })
}
