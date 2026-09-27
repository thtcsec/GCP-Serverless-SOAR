# Durable pending-approval records for REQUIRE_APPROVAL (survives function cold starts).
# Uses the project default Firestore database — matches firestore.Client() in ApprovalStore.

resource "google_project_service" "firestore_api" {
  project            = var.project_id
  service            = "firestore.googleapis.com"
  disable_on_destroy = false
}

resource "google_firestore_database" "approvals" {
  project     = var.project_id
  name        = "(default)"
  location_id = var.region
  type        = "FIRESTORE_NATIVE"

  depends_on = [google_project_service.firestore_api]
}

resource "google_project_iam_member" "soar_firestore_user" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.soar_function_sa.email}"
}

locals {
  approval_env = {
    APPROVAL_STORE                = "firestore"
    APPROVAL_FIRESTORE_COLLECTION = "soar_pending_approvals"
  }
}
