# Archive the function source code
data "archive_file" "function_zip" {
  type        = "zip"
  output_path = "${path.module}/soar_function.zip"
  source_dir  = "${path.module}/../src"
}

# Create a Cloud Storage bucket for the function source code
resource "google_storage_bucket" "function_bucket" {
  name     = "${var.project_id}-soar-functions-src"
  location = var.region

  uniform_bucket_level_access = true
}

# Upload the ZIP to the bucket
resource "google_storage_bucket_object" "function_archive" {
  name   = "soar-source-${data.archive_file.function_zip.output_md5}.zip"
  bucket = google_storage_bucket.function_bucket.name
  source = data.archive_file.function_zip.output_path
}

# Deploy the Cloud Function (2nd Gen) — primary Pub/Sub entry → handle_event()
resource "google_cloudfunctions2_function" "soar_responder_function" {
  name        = "soar-incident-responder"
  location    = var.region
  description = "Unified SOAR incident handler — delegates to handlers.handle_event pipeline"

  build_config {
    runtime     = "python312"
    entry_point = "soar_responder"
    source {
      storage_source {
        bucket = google_storage_bucket.function_bucket.name
        object = google_storage_bucket_object.function_archive.name
      }
    }
  }

  service_config {
    max_instance_count    = var.function_max_instances
    min_instance_count    = var.function_min_instances
    available_memory      = var.function_memory
    timeout_seconds       = var.function_timeout_seconds
    service_account_email = google_service_account.soar_function_sa.email

    environment_variables = {
      SLACK_WEBHOOK_URL = var.slack_webhook_url
      LAB_MOCK_INTEL    = var.lab_mock_intel ? "true" : "false"
      PROJECT_ID        = var.project_id
    }
  }

  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.scc_findings_topic.id
    retry_policy   = "RETRY_POLICY_DO_NOT_RETRY"
  }
}

# Optional audit-log responders (same pipeline; off by default for lab cost)
resource "google_cloudfunctions2_function" "sa_soar_responder_function" {
  count       = var.enable_audit_log_responders ? 1 : 0
  name        = "sa-soar-incident-responder"
  location    = var.region
  description = "SOAR adapter for IAM audit logs → handle_event()"

  build_config {
    runtime     = "python312"
    entry_point = "sa_compromise_responder"
    source {
      storage_source {
        bucket = google_storage_bucket.function_bucket.name
        object = google_storage_bucket_object.function_archive.name
      }
    }
  }

  service_config {
    max_instance_count    = var.function_max_instances
    min_instance_count    = var.function_min_instances
    available_memory      = var.function_memory
    timeout_seconds       = var.function_timeout_seconds
    service_account_email = google_service_account.soar_function_sa.email

    environment_variables = {
      PROJECT_ID     = var.project_id
      ALERT_TOPIC    = google_pubsub_topic.scc_findings_topic.name
      LAB_MOCK_INTEL = var.lab_mock_intel ? "true" : "false"
    }
  }

  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.audit.log.v1.written"
    retry_policy   = "RETRY_POLICY_DO_NOT_RETRY"
    event_filters {
      attribute = "serviceName"
      value     = "iam.googleapis.com"
    }
  }
}

resource "google_cloudfunctions2_function" "storage_soar_responder_function" {
  count       = var.enable_audit_log_responders ? 1 : 0
  name        = "storage-soar-incident-responder"
  location    = var.region
  description = "SOAR adapter for Storage audit logs → handle_event()"

  build_config {
    runtime     = "python312"
    entry_point = "storage_exfil_responder"
    source {
      storage_source {
        bucket = google_storage_bucket.function_bucket.name
        object = google_storage_bucket_object.function_archive.name
      }
    }
  }

  service_config {
    max_instance_count    = var.function_max_instances
    min_instance_count    = var.function_min_instances
    available_memory      = var.function_memory
    timeout_seconds       = var.function_timeout_seconds
    service_account_email = google_service_account.soar_function_sa.email

    environment_variables = {
      PROJECT_ID             = var.project_id
      ALERT_TOPIC            = google_pubsub_topic.scc_findings_topic.name
      EXFILTRATION_THRESHOLD = "10737418240"
      LAB_MOCK_INTEL         = var.lab_mock_intel ? "true" : "false"
    }
  }

  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.audit.log.v1.written"
    retry_policy   = "RETRY_POLICY_DO_NOT_RETRY"
    event_filters {
      attribute = "serviceName"
      value     = "storage.googleapis.com"
    }
  }
}
