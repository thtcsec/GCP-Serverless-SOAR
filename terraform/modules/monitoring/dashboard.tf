# GCP SOAR — Cloud Monitoring Dashboard
# Provides centralized visibility into SOAR platform health,
# incident metrics, and mean time to respond (MTTR).

# -------------------------------------------------------------------
# Variables
# -------------------------------------------------------------------
variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "cloud_function_names" {
  description = "List of Cloud Function names to monitor"
  type        = list(string)
  default     = ["soar-gce-containment", "soar-storage-exfil", "soar-sa-compromise"]
}

variable "pubsub_subscription" {
  description = "Pub/Sub subscription ID for incident messages"
  type        = string
  default     = "soar-incident-sub"
}

# -------------------------------------------------------------------
# Monitoring Dashboard
# -------------------------------------------------------------------
resource "google_monitoring_dashboard" "soar_dashboard" {
  project        = var.project_id
  dashboard_json = jsonencode({
    displayName = "SOAR Platform — ${var.environment}"
    mosaicLayout = {
      columns = 12
      tiles = [

        # --- Tile 1: Cloud Function Execution Count ---
        {
          xPos   = 0
          yPos   = 0
          width  = 6
          height = 4
          widget = {
            title = "Incident Volume (Function Executions)"
            xyChart = {
              dataSets = [for fn in var.cloud_function_names : {
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"cloudfunctions.googleapis.com/function/execution_count\" resource.type=\"cloud_function\" resource.label.\"function_name\"=\"${fn}\""
                    aggregation = {
                      alignmentPeriod  = "300s"
                      perSeriesAligner = "ALIGN_SUM"
                    }
                  }
                }
                plotType = "STACKED_BAR"
              }]
            }
          }
        },

        # --- Tile 2: Cloud Function Error Rate ---
        {
          xPos   = 6
          yPos   = 0
          width  = 6
          height = 4
          widget = {
            title = "Function Error Rate"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"cloudfunctions.googleapis.com/function/execution_count\" resource.type=\"cloud_function\" metric.label.\"status\"!=\"ok\""
                    aggregation = {
                      alignmentPeriod  = "300s"
                      perSeriesAligner = "ALIGN_SUM"
                    }
                  }
                }
                plotType = "LINE"
              }]
            }
          }
        },

        # --- Tile 3: Execution Duration / MTTR ---
        {
          xPos   = 0
          yPos   = 4
          width  = 6
          height = 4
          widget = {
            title = "Response Duration / MTTR (ms)"
            xyChart = {
              dataSets = [for fn in var.cloud_function_names : {
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"cloudfunctions.googleapis.com/function/execution_times\" resource.type=\"cloud_function\" resource.label.\"function_name\"=\"${fn}\""
                    aggregation = {
                      alignmentPeriod    = "300s"
                      perSeriesAligner   = "ALIGN_PERCENTILE_50"
                    }
                  }
                }
                plotType = "LINE"
              }]
            }
          }
        },

        # --- Tile 4: Pub/Sub Undelivered Messages ---
        {
          xPos   = 6
          yPos   = 4
          width  = 6
          height = 4
          widget = {
            title = "Pub/Sub Queue Depth (Pending Incidents)"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"pubsub.googleapis.com/subscription/num_undelivered_messages\" resource.type=\"pubsub_subscription\" resource.label.\"subscription_id\"=\"${var.pubsub_subscription}\""
                    aggregation = {
                      alignmentPeriod  = "60s"
                      perSeriesAligner = "ALIGN_MAX"
                    }
                  }
                }
                plotType = "LINE"
              }]
            }
          }
        },

        # --- Tile 5: Cloud Run Container Metrics ---
        {
          xPos   = 0
          yPos   = 8
          width  = 6
          height = 4
          widget = {
            title = "Cloud Run Forensic Workers — Request Count"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"run.googleapis.com/request_count\" resource.type=\"cloud_run_revision\""
                    aggregation = {
                      alignmentPeriod  = "300s"
                      perSeriesAligner = "ALIGN_SUM"
                    }
                  }
                }
                plotType = "STACKED_BAR"
              }]
            }
          }
        },

        # --- Tile 6: Cloud Workflows Execution Status ---
        {
          xPos   = 6
          yPos   = 8
          width  = 6
          height = 4
          widget = {
            title = "Cloud Workflows — Execution Status"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"workflows.googleapis.com/finished_execution_count\" resource.type=\"workflows.googleapis.com/Workflow\""
                    aggregation = {
                      alignmentPeriod  = "300s"
                      perSeriesAligner = "ALIGN_SUM"
                      groupByFields    = ["metric.label.\"status\""]
                    }
                  }
                }
                plotType = "STACKED_BAR"
              }]
            }
          }
        }
      ]
    }
  })
}

# -------------------------------------------------------------------
# Alerting Policies
# -------------------------------------------------------------------
resource "google_monitoring_alert_policy" "function_errors" {
  project      = var.project_id
  display_name = "SOAR Function Errors — ${var.environment}"
  combiner     = "OR"

  conditions {
    display_name = "Cloud Function execution errors"
    condition_threshold {
      filter          = "metric.type=\"cloudfunctions.googleapis.com/function/execution_count\" resource.type=\"cloud_function\" metric.label.\"status\"!=\"ok\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  alert_strategy {
    auto_close = "1800s"
  }
}

resource "google_monitoring_alert_policy" "pubsub_backlog" {
  project      = var.project_id
  display_name = "SOAR Pub/Sub Backlog — ${var.environment}"
  combiner     = "OR"

  conditions {
    display_name = "Undelivered messages in incident queue"
    condition_threshold {
      filter          = "metric.type=\"pubsub.googleapis.com/subscription/num_undelivered_messages\" resource.type=\"pubsub_subscription\" resource.label.\"subscription_id\"=\"${var.pubsub_subscription}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MAX"
      }
    }
  }

  alert_strategy {
    auto_close = "1800s"
  }
}

# -------------------------------------------------------------------
# Outputs
# -------------------------------------------------------------------
output "dashboard_id" {
  description = "ID of the SOAR monitoring dashboard"
  value       = google_monitoring_dashboard.soar_dashboard.id
}
