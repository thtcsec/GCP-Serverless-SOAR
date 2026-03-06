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
    runtime     = "python310"
    entry_point = "soar_responder"
    source {
      storage_source {
        bucket = google_storage_bucket.function_bucket.name
        object = google_storage_bucket_object.function_archive.name
      }
    }
  }

  service_config {
    max_instance_count = 1
    available_memory   = "256M"
    timeout_seconds    = 60
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
