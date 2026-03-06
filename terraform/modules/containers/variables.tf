variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "isolation_worker_image" {
  description = "Container image for isolation worker"
  type        = string
  default     = "us-central1-docker.pkg.dev/PROJECT_ID/soar-containers/isolation-worker:latest"
}

variable "forensics_worker_image" {
  description = "Container image for forensics worker"
  type        = string
  default     = "us-central1-docker.pkg.dev/PROJECT_ID/soar-containers/forensics-worker:latest"
}

variable "isolation_firewall_name" {
  description = "Name of the isolation firewall rule"
  type        = string
  default     = "soar-isolation-firewall"
}

variable "labels" {
  description = "Common labels to apply to all resources"
  type        = map(string)
  default = {
    project     = "soar"
    managed-by  = "terraform"
    environment = "production"
  }
}
