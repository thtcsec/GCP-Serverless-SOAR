# Create a dedicated Service Account for the VM
resource "google_service_account" "vm_sa" {
  account_id   = "soar-target-vm-sa"
  display_name = "SOAR Target VM Service Account"
}

# Vulnerable Compute Engine Instance
resource "google_compute_instance" "target_vm" {
  name         = "gce-target-01"
  machine_type = "e2-micro"
  zone         = var.zone

  tags = ["allow-ssh"] # Initial tag. Will be replaced by 'isolated-vm' by SOAR

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
      size  = 10
    }
  }

  network_interface {
    network = google_compute_network.soar_vpc.name
    access_config {
      // Ephemeral public IP
    }
  }

  service_account {
    email  = google_service_account.vm_sa.email
    scopes = ["cloud-platform"] # Intentionally broad for demo, attacker could abuse this
  }
}
