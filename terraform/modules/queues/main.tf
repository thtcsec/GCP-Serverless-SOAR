# Enterprise SOAR GCP Queues Module
# Pub/Sub with Dead Letter Topics for message buffering

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
# Main Pub/Sub Topics
# ==========================================
resource "google_pubsub_topic" "security_events" {
  name = "${var.environment}-soar-security-events"
  
  labels = merge(
    var.labels,
    {
      environment = var.environment
      purpose     = "security-events"
    }
  )

  message_retention_duration = "604800s" # 7 days

  # Enable message ordering
  enable_message_ordering = false
}

# ==========================================
# Dead Letter Topics
# ==========================================
resource "google_pubsub_topic" "security_events_dlq" {
  name = "${var.environment}-soar-security-events-dlq"
  
  labels = merge(
    var.labels,
    {
      environment = var.environment
      purpose     = "dead-letter-queue"
    }
  )

  message_retention_duration = "1209600s" # 14 days
}

# ==========================================
# Pub/Sub Subscriptions
# ==========================================
resource "google_pubsub_subscription" "security_events_subscription" {
  name  = "${var.environment}-soar-security-events-sub"
  topic = google_pubsub_topic.security_events.name

  # Dead Letter Policy
  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.security_events_dlq.id
    max_delivery_attempts = 5
  }

  # Retry Policy
  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  # Message retention
  message_retention_duration = "86400s" # 1 day

  # Acknowledgement deadline
  ack_deadline = 300 # 5 minutes

  # Enable exactly-once delivery
  enable_exactly_once_delivery = true

  labels = merge(
    var.labels,
    {
      environment = var.environment
      purpose     = "event-processing"
    }
  )
}

# ==========================================
# Cloud Run Workers for Message Processing
# ==========================================
resource "google_cloud_run_service" "message_processor" {
  name     = "${var.environment}-soar-message-processor"
  location = var.region

  template {
    spec {
      containers {
        image = var.message_processor_image
        
        resources {
          limits = {
            cpu    = "1000m"
            memory = "512Mi"
          }
        }

        env {
          name  = "PROJECT_ID"
          value = var.project_id
        }

        env {
          name  = "ENVIRONMENT"
          value = var.environment
        }

        env {
          name = "WORKFLOW_EXECUTION_SERVICE_URL"
          value = "https://workflowexecutions.googleapis.com/v1"
        }

        env {
          name  = "LOG_LEVEL"
          value = "INFO"
        }
      }

      container_concurrency = 10
      timeout_seconds       = 300
    }
  }

  traffic {
    percent = 100
    latest_revision = true
  }

  labels = merge(
    var.labels,
    {
      environment = var.environment
      purpose     = "message-processing"
    }
  )
}

# ==========================================
# Cloud Run Service Account
# ==========================================
resource "google_service_account" "message_processor_sa" {
  account_id   = "${var.environment}-soar-message-processor"
  display_name = "SOAR Message Processor Service Account"
  description  = "Service account for SOAR message processor Cloud Run service"

  labels = merge(
    var.labels,
    {
      environment = var.environment
      purpose     = "message-processing"
    }
  )
}

# ==========================================
# IAM Permissions
# ==========================================
resource "google_cloud_run_service_iam_member" "message_processor_invoker" {
  location = google_cloud_run_service.message_processor.location
  project  = google_cloud_run_service.message_processor.project
  service  = google_cloud_run_service.message_processor.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.message_processor_sa.email}"
}

resource "google_project_iam_member" "pubsub_subscriber" {
  project = var.project_id
  role    = "roles/pubsub.subscriber"
  member  = "serviceAccount:${google_service_account.message_processor_sa.email}"
}

resource "google_project_iam_member" "workflow_invoker" {
  project = var.project_id
  role    = "roles/workflows.invoker"
  member  = "serviceAccount:${google_service_account.message_processor_sa.email}"
}

# ==========================================
# Pub/Sub Push Subscription to Cloud Run
# ==========================================
resource "google_pubsub_subscription" "security_events_push" {
  name  = "${var.environment}-soar-security-events-push"
  topic = google_pubsub_topic.security_events.name

  push_config {
    push_endpoint = google_cloud_run_service.message_processor.status[0].url
    oidc_token {
      service_account_email = google_service_account.message_processor_sa.email
      audience             = google_cloud_run_service.message_processor.status[0].url
    }
    attributes = {
      "x-goog-version" = "v1"
    }
  }

  # Dead Letter Policy
  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.security_events_dlq.id
    max_delivery_attempts = 5
  }

  # Acknowledgement deadline for push
  ack_deadline = 600 # 10 minutes

  labels = merge(
    var.labels,
    {
      environment = var.environment
      purpose     = "push-processing"
    }
  )
}

# ==========================================
# Eventarc Triggers for Security Events
# ==========================================
resource "google_eventarc_trigger" "scc_findings_trigger" {
  name     = "${var.environment}-soar-scc-findings"
  location = var.region

  event_type = "google.cloud.securitycenter.v1.FindingPublished"
  
  service_account = google_service_account.message_processor_sa.email

  destination {
    cloud_run {
      service = google_cloud_run_service.message_processor.name
      region  = var.region
    }
  }

  filtering {
    attribute = "type"
    value     = "google.cloud.securitycenter.v1.FindingPublished"
  }

  labels = merge(
    var.labels,
    {
      environment = var.environment
      purpose     = "scc-findings"
    }
  )
}

resource "google_eventarc_trigger" "audit_log_trigger" {
  name     = "${var.environment}-soar-audit-logs"
  location = var.region

  event_type = "google.cloud.audit.log.v1.written"
  
  service_account = google_service_account.message_processor_sa.email

  destination {
    cloud_run {
      service = google_cloud_run_service.message_processor.name
      region  = var.region
    }
  }

  filtering {
    attribute = "methodName"
    value     = "compute.instances.insert"
  }

  labels = merge(
    var.labels,
    {
      environment = var.environment
      purpose     = "audit-logs"
    }
  )
}
