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

# Deploy the Cloud Function (2nd Gen)
resource "google_cloudfunctions2_function" "soar_responder_function" {
  name        = "soar-incident-responder"
  location    = var.region
  description = "SOAR Python webhook to isolate compromised VMs"

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
    max_instance_count = var.function_max_instances
    min_instance_count = var.function_min_instances
    available_memory   = var.function_memory
    timeout_seconds    = var.function_timeout_seconds
    service_account_email = google_service_account.soar_function_sa.email
    
    environment_variables = {
      SLACK_WEBHOOK_URL = var.slack_webhook_url
    }
  }

  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.scc_findings_topic.id
    retry_policy   = "RETRY_POLICY_DO_NOT_RETRY"
  }
}

# Deploy SA Compromise Responder
resource "google_cloudfunctions2_function" "sa_soar_responder_function" {
  name        = "sa-soar-incident-responder"
  location    = var.region
  description = "SOAR Python webhook to respond to SA compromise"

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
    max_instance_count = var.function_max_instances
    min_instance_count = var.function_min_instances
    available_memory   = var.function_memory
    timeout_seconds    = var.function_timeout_seconds
    service_account_email = google_service_account.soar_function_sa.email
    
    environment_variables = {
      PROJECT_ID = var.project_id
      ALERT_TOPIC = google_pubsub_topic.scc_findings_topic.name
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

# Deploy Storage Exfil Responder
resource "google_cloudfunctions2_function" "storage_soar_responder_function" {
  name        = "storage-soar-incident-responder"
  location    = var.region
  description = "SOAR Python webhook to respond to Storage exfiltration"

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
    max_instance_count = var.function_max_instances
    min_instance_count = var.function_min_instances
    available_memory   = var.function_memory
    timeout_seconds    = var.function_timeout_seconds
    service_account_email = google_service_account.soar_function_sa.email
    
    environment_variables = {
      PROJECT_ID = var.project_id
      ALERT_TOPIC  = google_pubsub_topic.scc_findings_topic.name
      EXFILTRATION_THRESHOLD = "10737418240"
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
