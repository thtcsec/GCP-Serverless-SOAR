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
  
  target_tags = ["allow-ssh"]
}

# ---------------------------------------------------------
# ISOLATION FIREWALL RULES
# Applied automatically by SOAR Cloud Function
# ---------------------------------------------------------

# Block ALL external Ingress
resource "google_compute_firewall" "deny_all" {
  name    = "soar-isolation-deny-ingress"
  network = google_compute_network.soar_vpc.name

  priority  = 100
  direction = "INGRESS"

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["isolated-vm"]
}

# Block ALL Egress (Stops C&C callbacks, data exfiltration)
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

# Exception: Allow strictly controlled SSH access for Forensic Investigation
resource "google_compute_firewall" "allow_forensic_ssh" {
  name    = "soar-isolation-allow-forensic-ssh"
  network = google_compute_network.soar_vpc.name

  priority  = 90 # Higher priority than deny_all (100)
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  # In a prod environment, limit this to the IP of the SOC Team's jump box
  # Example: source_ranges = ["192.168.1.100/32"]
  source_ranges = [var.forensic_jump_host_ip]
  target_tags   = ["isolated-vm"]
}
