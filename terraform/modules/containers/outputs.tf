output "isolation_worker_url" {
  description = "URL of the isolation worker Cloud Run service"
  value       = google_cloud_run_service.isolation_worker.status[0].url
}

output "forensics_worker_url" {
  description = "URL of the forensics worker Cloud Run service"
  value       = google_cloud_run_service.forensics_worker.status[0].url
}

output "forensics_bucket_name" {
  description = "Name of the forensics storage bucket"
  value       = google_storage_bucket.forensics_bucket.name
}

output "artifact_registry_repository" {
  description = "Name of the Artifact Registry repository"
  value       = google_artifact_registry_repository.soar_containers.name
}

output "isolation_worker_service_account" {
  description = "Email of the isolation worker service account"
  value       = google_service_account.isolation_worker_sa.email
}

output "forensics_worker_service_account" {
  description = "Email of the forensics worker service account"
  value       = google_service_account.forensics_worker_sa.email
}
