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

variable "org_id" {
  description = "GCP Organization ID (required for org-level SCC export)"
  type        = string
  default     = ""
}

variable "enable_cross_project_access" {
  description = "Whether to create cross-project responder SA and bindings"
  type        = bool
  default     = true
}

variable "target_project_ids" {
  description = "List of GCP project IDs where the SOAR can respond to incidents"
  type        = list(string)
  default     = []
}

variable "labels" {
  description = "Common labels to apply to all resources"
  type        = map(string)
  default = {
    project    = "soar"
    managed-by = "terraform"
  }
}
