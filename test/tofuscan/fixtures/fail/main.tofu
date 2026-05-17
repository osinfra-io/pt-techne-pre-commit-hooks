# GCP CIS 3.6 — SSH access must not be open to the internet
resource "google_compute_firewall" "allow_ssh" {
  name    = "allow-ssh-from-internet"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
}

# GCP CIS 3.7 — RDP access must not be open to the internet
resource "google_compute_firewall" "allow_rdp" {
  name    = "allow-rdp-from-internet"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }

  source_ranges = ["0.0.0.0/0"]
}

# GCP CIS 4.1 — default service account used (service_account.email)
# GCP CIS 4.2 — default service account with cloud-platform scope
# GCP CIS 4.3 — block-project-ssh-keys not set in metadata
# GCP CIS 4.5 — serial-port-enable = true in metadata
# GCP CIS 4.6 — can_ip_forward = true
# GCP CIS 4.8 — shielded_instance_config absent
# GCP CIS 4.9 — access_config present (public IP)
# GCP CIS 4.11 — confidential_instance_config absent
resource "google_compute_instance" "vm" {
  name         = "my-vm"
  machine_type = "n1-standard-1"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = "default"
    access_config {}
  }

  can_ip_forward = true

  metadata = {
    "serial-port-enable" = "true"
  }

  service_account {
    email  = "123456789-compute@developer.gserviceaccount.com"
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }
}

# GCP CIS 5.2 — uniform_bucket_level_access absent (defaults to false)
resource "google_storage_bucket" "bucket" {
  name     = "my-bucket"
  location = "US"
}

# GCP CIS 1.5 — service account assigned an admin/editor role
resource "google_project_iam_member" "bad_iam" {
  project = "my-project"
  role    = "roles/editor"
  member  = "serviceAccount:my-sa@my-project.iam.gserviceaccount.com"
}

# GCP CIS 1.7 — user-managed key exists (should use GOOGLE_MANAGED)
resource "google_iam_service_account_key" "bad_key" {
  service_account_id = "my-sa@my-project.iam.gserviceaccount.com"
  key_type           = "USER_MANAGED"
}

# GCP CIS 1.10 — rotation_period exceeds 90 days (7776000s)
resource "google_kms_crypto_key" "bad_key" {
  name            = "bad-key"
  key_ring        = "projects/my-project/locations/global/keyRings/my-ring"
  rotation_period = "15552001s"
}

# GCP CIS 3.3 — DNSSEC state = "off"
# GCP CIS 3.4 — DNSSEC key-signing algorithm = rsasha1
resource "google_dns_managed_zone" "bad_zone" {
  name     = "bad-zone"
  dns_name = "bad.example.com."

  dnssec_config {
    state = "off"

    default_key_specs {
      algorithm  = "rsasha1"
      key_type   = "keySigning"
      key_length = 2048
    }
  }
}

# GCP CIS 3.8 — log_config block absent (VPC flow logs disabled)
resource "google_compute_subnetwork" "bad_subnet" {
  name          = "bad-subnet"
  ip_cidr_range = "10.0.0.0/24"
  network       = "default"
  region        = "us-central1"
}

# GCP CIS 5.1 — bucket IAM grants access to allUsers
resource "google_storage_bucket_iam_member" "bad_member" {
  bucket = "my-bucket"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

# GCP CIS 5.1 — bucket IAM binding grants access to allAuthenticatedUsers
resource "google_storage_bucket_iam_binding" "bad_binding" {
  bucket  = "my-bucket"
  role    = "roles/storage.objectViewer"
  members = ["allAuthenticatedUsers"]
}

# GCP CIS 6.4 — ssl_mode = ALLOW_UNENCRYPTED_AND_ENCRYPTED (unencrypted connections permitted)
# GCP CIS 6.5 — authorized_networks contains 0.0.0.0/0
# GCP CIS 6.6 — ipv4_enabled = true (public IP)
# GCP CIS 6.7 — backup_configuration block absent
# GCP CIS 6.2.1 — log_error_verbosity = VERBOSE
# GCP CIS 6.2.2 — log_connections absent
# GCP CIS 6.2.3 — log_disconnections absent
# GCP CIS 6.2.4 — log_statement = none
# GCP CIS 6.2.5 — log_min_messages = DEBUG5
# GCP CIS 6.2.6 — log_min_error_statement = WARNING
# GCP CIS 6.2.7 — log_min_duration_statement = 0 (logs all statements; disclose query literals)
# GCP CIS 6.2.8 — cloudsql.enable_pgaudit absent
resource "google_sql_database_instance" "bad_sql" {
  name             = "bad-sql"
  database_version = "POSTGRES_14"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ssl_mode     = "ALLOW_UNENCRYPTED_AND_ENCRYPTED"
      ipv4_enabled = true

      authorized_networks {
        value = "0.0.0.0/0"
      }
    }

    database_flags {
      name  = "log_error_verbosity"
      value = "VERBOSE"
    }

    database_flags {
      name  = "log_statement"
      value = "none"
    }

    database_flags {
      name  = "log_min_messages"
      value = "DEBUG5"
    }

    database_flags {
      name  = "log_min_error_statement"
      value = "WARNING"
    }

    database_flags {
      name  = "log_min_duration_statement"
      value = "0"
    }
  }
}

# GCP CIS 7.1 — BigQuery dataset grants access to allUsers
resource "google_bigquery_dataset" "bad_dataset" {
  dataset_id = "bad_dataset"

  access {
    role          = "READER"
    special_group = "allUsers"
  }
}

# GCP CIS 2.2 — project resource present but no log sink defined
resource "google_project" "bad_project" {
  name       = "bad-project"
  project_id = "bad-project-id"
}

# GKE CIS 5.6.3 — master_authorized_networks_config present but no cidr_blocks
# GKE CIS 5.10.2 — enable_kubernetes_alpha = true
# GKE CIS 5.10.4 — binary_authorization block absent
# Note: 5.10.1 (kubernetes_dashboard) was removed from the Google provider;
#       the block is no longer valid and the dashboard is permanently disabled in GKE.
resource "google_container_cluster" "bad_cluster" {
  name     = "bad-cluster"
  location = "us-central1"

  enable_shielded_nodes   = false
  enable_legacy_abac      = true
  enable_kubernetes_alpha = true

  logging_service    = "none"
  monitoring_service = "none"

  networking_mode = "ROUTES"

  release_channel {
    channel = "UNSPECIFIED"
  }

  database_encryption {
    state    = "DECRYPTED"
    key_name = ""
  }

  private_cluster_config {
    enable_private_endpoint = false
    enable_private_nodes    = false
  }

  # GKE CIS 5.6.3 — master_authorized_networks_config present but no cidr_blocks
  master_authorized_networks_config {
  }

  master_auth {
    client_certificate_config {
      issue_client_certificate = true
    }
  }

  addons_config {
  }
}

# GKE CIS 5.2.1 — service_account = "default" (should use dedicated SA)
# GKE CIS 5.4.1 — workload_metadata_config.mode = EXPOSE (not GKE_METADATA)
# GKE CIS 5.5.1 — image_type = UBUNTU_CONTAINERD (not COS_CONTAINERD)
# GKE CIS 5.5.2 — management.auto_repair = false
# GKE CIS 5.5.3 — management.auto_upgrade = false
# GKE CIS 5.5.6 — shielded_instance_config.enable_integrity_monitoring = false
# GKE CIS 5.5.7 — shielded_instance_config.enable_secure_boot = false
resource "google_container_node_pool" "bad_pool" {
  name    = "bad-pool"
  cluster = "bad-cluster"

  management {
    auto_repair  = false
    auto_upgrade = false
  }

  node_config {
    image_type      = "UBUNTU_CONTAINERD"
    service_account = "default"

    shielded_instance_config {
      enable_integrity_monitoring = false
      enable_secure_boot          = false
    }

    workload_metadata_config {
      mode = "EXPOSE"
    }
  }
}

# GCP CIS 1.6 — serviceAccountUser role granted at project level
resource "google_project_iam_member" "bad_sa_user" {
  project = "my-project"
  role    = "roles/iam.serviceAccountUser"
  member  = "user:someone@example.com"
}

# GCP CIS 1.9 — KMS cryptokey IAM grants access to allUsers
resource "google_kms_crypto_key_iam_member" "bad_kms_iam" {
  crypto_key_id = "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key"
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "allUsers"
}

# GCP CIS 3.1 — default VPC network present in project
resource "google_compute_network" "default" {
  name = "default"
}

# GCP CIS 3.9 — SSL policy uses COMPATIBLE profile (allows weak cipher suites)
resource "google_compute_ssl_policy" "bad_ssl_policy" {
  name    = "bad-ssl-policy"
  profile = "COMPATIBLE"
}

# GCP CIS 4.7 — disk has no customer-supplied encryption key
resource "google_compute_disk" "bad_disk" {
  name = "bad-disk"
  type = "pd-ssd"
  zone = "us-central1-a"
}

# GCP CIS 6.1.2 — MySQL skip_show_database flag absent
# GCP CIS 6.1.3 — MySQL local_infile flag absent (defaults to on)
resource "google_sql_database_instance" "bad_mysql" {
  name             = "bad-mysql"
  database_version = "MYSQL_8_0"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ssl_mode     = "ENCRYPTED_ONLY"
      ipv4_enabled = false
    }

    backup_configuration {
      enabled = true
    }
  }
}

# GCP CIS 6.3.1 — SQL Server external scripts enabled flag absent (defaults to on)
# GCP CIS 6.3.2 — SQL Server cross db ownership chaining flag absent (defaults to on)
# GCP CIS 6.3.5 — SQL Server remote access flag absent (defaults to on)
# GCP CIS 6.3.6 — SQL Server trace flag 3625 absent (error messages not masked)
# GCP CIS 6.3.7 — SQL Server contained database authentication flag absent (defaults to on)
resource "google_sql_database_instance" "bad_sqlserver" {
  name             = "bad-sqlserver"
  database_version = "SQLSERVER_2017_STANDARD"

  settings {
    tier = "db-custom-1-3840"

    ip_configuration {
      ssl_mode     = "ENCRYPTED_ONLY"
      ipv4_enabled = false
    }

    backup_configuration {
      enabled = true
    }
  }
}

# GCP CIS 7.2 — BigQuery table has no customer-managed encryption key
resource "google_bigquery_table" "bad_bigquery_table" {
  dataset_id = "bad_dataset"
  table_id   = "bad_table"
}
