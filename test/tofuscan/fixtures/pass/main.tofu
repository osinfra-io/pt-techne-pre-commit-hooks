# GCP CIS 3.6 — SSH restricted to internal ranges only (not 0.0.0.0/0)
resource "google_compute_firewall" "allow_ssh_internal" {
  name    = "allow-ssh-internal"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["10.0.0.0/8"]
}

# GCP CIS 3.7 — RDP restricted to internal ranges only (not 0.0.0.0/0)
resource "google_compute_firewall" "allow_rdp_internal" {
  name    = "allow-rdp-internal"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }

  source_ranges = ["10.0.0.0/8"]
}

# GCP CIS 4.1/4.2 — no service_account block (no default SA used)
# GCP CIS 4.3 — block-project-ssh-keys = "true" in metadata
# GCP CIS 4.5 — serial-port-enable absent in metadata
# GCP CIS 4.6 — can_ip_forward = false
# GCP CIS 4.8 — shielded_instance_config present with vtpm + integrity monitoring
# GCP CIS 4.9 — no access_config (no public IP)
# GCP CIS 4.11 — confidential_instance_config.enable_confidential_compute = true
resource "google_compute_instance" "vm" {
  name         = "my-vm"
  machine_type = "n2d-standard-2"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = "default"
  }

  can_ip_forward = false

  metadata = {
    block-project-ssh-keys = "true"
  }

  shielded_instance_config {
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  confidential_instance_config {
    enable_confidential_compute = true
  }
}

# GCP CIS 5.2 — uniform_bucket_level_access = true
resource "google_storage_bucket" "bucket" {
  name                        = "my-secure-bucket"
  location                    = "US"
  uniform_bucket_level_access = true
}

# GCP CIS 2.2 — project resource with log sink present
resource "google_project" "good_project" {
  name       = "good-project"
  project_id = "good-project-id"
}

resource "google_logging_project_sink" "main" {
  name        = "main-sink"
  destination = "storage.googleapis.com/my-log-bucket"
}

# GCP CIS 1.5 — service account assigned a non-admin role (roles/viewer)
resource "google_project_iam_member" "good_iam" {
  project = "my-project"
  role    = "roles/viewer"
  member  = "serviceAccount:my-sa@my-project.iam.gserviceaccount.com"
}

# GCP CIS 1.7 — key_type = GOOGLE_MANAGED (not user-managed)
resource "google_iam_service_account_key" "good_key" {
  service_account_id = "my-sa@my-project.iam.gserviceaccount.com"
  key_type           = "GOOGLE_MANAGED"
}

# GCP CIS 1.10 — rotation_period = 7776000s (exactly 90 days)
resource "google_kms_crypto_key" "good_key" {
  name            = "good-key"
  key_ring        = "projects/my-project/locations/global/keyRings/my-ring"
  rotation_period = "7776000s"
}

# GCP CIS 3.3 — DNSSEC state = "on"
# GCP CIS 3.4 — DNSSEC algorithm = rsasha256 (not rsasha1)
resource "google_dns_managed_zone" "good_zone" {
  name     = "good-zone"
  dns_name = "good.example.com."

  dnssec_config {
    state = "on"

    default_key_specs {
      algorithm  = "rsasha256"
      key_type   = "keySigning"
      key_length = 2048
    }
  }
}

# GCP CIS 3.8 — log_config present (VPC flow logs enabled)
resource "google_compute_subnetwork" "good_subnet" {
  name          = "good-subnet"
  ip_cidr_range = "10.0.0.0/24"
  network       = "default"
  region        = "us-central1"

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
  }
}

# GCP CIS 5.1 — IAM member is a specific user, not allUsers/allAuthenticatedUsers
resource "google_storage_bucket_iam_member" "good_member" {
  bucket = "my-secure-bucket"
  role   = "roles/storage.objectViewer"
  member = "user:someone@example.com"
}

# GCP CIS 6.4 — ssl_mode = TRUSTED_CLIENT_CERTIFICATE_REQUIRED (encrypted only)
# GCP CIS 6.5 — no 0.0.0.0/0 in authorized_networks
# GCP CIS 6.6 — ipv4_enabled = false (private IP only)
# GCP CIS 6.7 — backup_configuration.enabled = true
resource "google_sql_database_instance" "good_sql" {
  name             = "good-sql"
  database_version = "POSTGRES_14"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ssl_mode     = "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"
      ipv4_enabled = false
    }

    backup_configuration {
      enabled = true
    }
  }
}

# GCP CIS 7.1 — access granted to a specific user, not allUsers/allAuthenticatedUsers
resource "google_bigquery_dataset" "good_dataset" {
  dataset_id = "good_dataset"

  access {
    role          = "READER"
    user_by_email = "someone@example.com"
  }
}

# GKE CIS 5.10.2 — enable_kubernetes_alpha absent (defaults to false)
# GKE CIS 5.10.4 — binary_authorization.evaluation_mode != DISABLED
# Note: 5.10.1 (kubernetes_dashboard) was removed from the Google provider;
#       the block is no longer valid and the dashboard is permanently disabled in GKE.
resource "google_container_cluster" "good_cluster" {
  name     = "good-cluster"
  location = "us-central1"

  enable_shielded_nodes = true
  enable_legacy_abac    = false

  logging_service    = "logging.googleapis.com/kubernetes"
  monitoring_service = "monitoring.googleapis.com/kubernetes"

  networking_mode = "VPC_NATIVE"

  ip_allocation_policy {}

  release_channel {
    channel = "REGULAR"
  }

  database_encryption {
    state    = "ENCRYPTED"
    key_name = "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key"
  }

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "10.0.0.0/8"
      display_name = "internal"
    }
  }

  private_cluster_config {
    enable_private_endpoint = true
    enable_private_nodes    = true
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  addons_config {
  }

  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }
}

# GKE CIS 5.2.1 — dedicated service account (not "default")
# GKE CIS 5.4.1 — workload_metadata_config.mode = GKE_METADATA
# GKE CIS 5.5.1 — image_type = COS_CONTAINERD
# GKE CIS 5.5.2 — management.auto_repair = true
# GKE CIS 5.5.3 — management.auto_upgrade = true
# GKE CIS 5.5.6 — shielded_instance_config.enable_integrity_monitoring = true
# GKE CIS 5.5.7 — shielded_instance_config.enable_secure_boot = true
resource "google_container_node_pool" "good_pool" {
  name    = "good-pool"
  cluster = "good-cluster"

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  node_config {
    image_type      = "COS_CONTAINERD"
    service_account = "my-gke-sa@my-project.iam.gserviceaccount.com"

    shielded_instance_config {
      enable_integrity_monitoring = true
      enable_secure_boot          = true
    }

    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }
}
