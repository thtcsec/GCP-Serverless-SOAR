# Default VPC Network
resource "google_compute_network" "soar_vpc" {
  name                    = "soar-vpc"
  auto_create_subnetworks = true
}

# Firewall: Allow SSH for testing
resource "google_compute_firewall" "allow_ssh" {
  name    = "soar-allow-ssh"
  network = google_compute_network.soar_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["0.0.0.0/0"]
  
  # DO NOT apply this to isolated-vm tag.
  target_tags = ["allow-ssh"]
}

# Firewall: Isolation Rule -> Block ALL ingress and egress
resource "google_compute_firewall" "deny_all" {
  name    = "soar-isolation-deny-all"
  network = google_compute_network.soar_vpc.name

  # High priority to override any allows
  priority  = 100
  direction = "INGRESS"

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["isolated-vm"]
}

resource "google_compute_firewall" "deny_all_egress" {
  name    = "soar-isolation-deny-egress"
  network = google_compute_network.soar_vpc.name

  priority  = 100
  direction = "EGRESS"

  deny {
    protocol = "all"
  }

  destination_ranges = ["0.0.0.0/0"]
  target_tags        = ["isolated-vm"]
}
