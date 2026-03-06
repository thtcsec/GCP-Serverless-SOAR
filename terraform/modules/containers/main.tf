# Enterprise SOAR GCP Containers Module
# Cloud Run services for long-running operations

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
# Isolation Worker Cloud Run Service
# ==========================================
resource "google_cloud_run_service" "isolation_worker" {
  name     = "${var.environment}-soar-isolation-worker"
  location = var.region

  template {
    spec {
      containers {
        image = var.isolation_worker_image
        
        resources {
          limits = {
            cpu    = "1000m"
            memory = "1Gi"
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
          name  = "ISOLATION_FIREWALL_NAME"
          value = var.isolation_firewall_name
        }

        env {
          name  = "LOG_LEVEL"
          value = "INFO"
        }

        # Health check
        startup_probe {
          http_get {
            path = "/health"
            port = 8080
          }
          initial_delay_seconds = 10
          timeout_seconds        = 5
          period_seconds         = 10
          failure_threshold      = 3
        }

        liveness_probe {
          http_get {
            path = "/health"
            port = 8080
          }
          initial_delay_seconds = 30
          timeout_seconds        = 5
          period_seconds         = 10
          failure_threshold      = 3
        }
      }

      container_concurrency = 10
      timeout_seconds       = 600 # 10 minutes for isolation operations
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
      purpose     = "isolation-worker"
    }
  )
}

# ==========================================
# Forensics Worker Cloud Run Service
# ==========================================
resource "google_cloud_run_service" "forensics_worker" {
  name     = "${var.environment}-soar-forensics-worker"
  location = var.region

  template {
    spec {
      containers {
        image = var.forensics_worker_image
        
        resources {
          limits = {
            cpu    = "2000m"
            memory = "4Gi"
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
          name  = "FORENSICS_BUCKET"
          value = google_storage_bucket.forensics_bucket.name
        }

        env {
          name  = "LOG_LEVEL"
          value = "INFO"
        }

        # Health check
        startup_probe {
          http_get {
            path = "/health"
            port = 8080
          }
          initial_delay_seconds = 30
          timeout_seconds        = 10
          period_seconds         = 20
          failure_threshold      = 3
        }

        liveness_probe {
          http_get {
            path = "/health"
            port = 8080
          }
          initial_delay_seconds = 60
          timeout_seconds        = 10
          period_seconds         = 30
          failure_threshold      = 3
        }
      }

      container_concurrency = 1 # Forensics is resource-intensive, run one at a time
      timeout_seconds       = 3600 # 1 hour for forensic operations
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
      purpose     = "forensics-worker"
    }
  )
}

# ==========================================
# Service Accounts
# ==========================================
resource "google_service_account" "isolation_worker_sa" {
  account_id   = "${var.environment}-soar-isolation-worker"
  display_name = "SOAR Isolation Worker Service Account"
  description  = "Service account for SOAR isolation worker Cloud Run service"

  labels = merge(
    var.labels,
    {
      environment = var.environment
      purpose     = "isolation-worker"
    }
  )
}

resource "google_service_account" "forensics_worker_sa" {
  account_id   = "${var.environment}-soar-forensics-worker"
  display_name = "SOAR Forensics Worker Service Account"
  description  = "Service account for SOAR forensics worker Cloud Run service"

  labels = merge(
    var.labels,
    {
      environment = var.environment
      purpose     = "forensics-worker"
    }
  )
}

# ==========================================
# IAM Permissions
# ==========================================
resource "google_cloud_run_service_iam_member" "isolation_worker_invoker" {
  location = google_cloud_run_service.isolation_worker.location
  project  = google_cloud_run_service.isolation_worker.project
  service  = google_cloud_run_service.isolation_worker.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.isolation_worker_sa.email}"
}

resource "google_cloud_run_service_iam_member" "forensics_worker_invoker" {
  location = google_cloud_run_service.forensics_worker.location
  project  = google_cloud_run_service.forensics_worker.project
  service  = google_cloud_run_service.forensics_worker.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.forensics_worker_sa.email}"
}

# Compute permissions for isolation worker
resource "google_project_iam_member" "isolation_worker_compute" {
  project = var.project_id
  role    = "roles/compute.securityAdmin"
  member  = "serviceAccount:${google_service_account.isolation_worker_sa.email}"
}

resource "google_project_iam_member" "isolation_worker_viewer" {
  project = var.project_id
  role    = "roles/compute.viewer"
  member  = "serviceAccount:${google_service_account.isolation_worker_sa.email}"
}

# Storage permissions for forensics worker
resource "google_project_iam_member" "forensics_worker_storage" {
  project = var.project_id
  role    = "roles/storage.objectAdmin"
  member  = "serviceAccount:${google_service_account.forensics_worker_sa.email}"
}

resource "google_project_iam_member" "forensics_worker_compute" {
  project = var.project_id
  role    = "roles/compute.viewer"
  member  = "serviceAccount:${google_service_account.forensics_worker_sa.email}"
}

# ==========================================
# Storage Bucket for Forensics
# ==========================================
resource "google_storage_bucket" "forensics_bucket" {
  name          = "${var.project_id}-soar-forensics-${var.environment}"
  location      = var.region
  storage_class = "STANDARD"
  
  uniform_bucket_level_access = true

  labels = merge(
    var.labels,
    {
      environment = var.environment
      purpose     = "forensics-storage"
    }
  )

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 90 # Delete after 90 days
    }
    action {
      type = "Delete"
    }
  }
}

# ==========================================
# Artifact Registry for Container Images
# ==========================================
resource "google_artifact_registry_repository" "soar_containers" {
  location      = var.region
  repository_id = "soar-containers"
  description   = "SOAR container images repository"
  format        = "DOCKER"

  labels = merge(
    var.labels,
    {
      environment = var.environment
      purpose     = "container-registry"
    }
  )
}
