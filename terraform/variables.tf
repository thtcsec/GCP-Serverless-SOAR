variable "project_id" {
  description = "The GCP Project ID where resources will be deployed"
  type        = string
}

variable "region" {
  description = "The GCP region to deploy resources in"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "The GCP zone for the Compute Engine instance"
  type        = string
  default     = "us-central1-a"
}

variable "alert_email" {
  description = "Email address to receive GuardDuty SOAR alerts (Note: GCP uses PubSub/Email integrations or direct Sengrid/Slack webhooks. We will just use standard Cloud Logging here for simplicity, but in a real case add an Email sink)"
  type        = string
  default     = "admin@example.com"
}
