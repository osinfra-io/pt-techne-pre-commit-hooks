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

# GCP CIS 4.1 — dedicated service account (not default)
# GCP CIS 4.3 — block-project-ssh-keys = "true" in metadata
# GCP CIS 4.4 — enable-oslogin = "true" in metadata
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
    enable-oslogin         = "true"
  }

  shielded_instance_config {
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  confidential_instance_config {
    enable_confidential_compute = true
  }

  service_account {
    email  = "my-sa@my-project.iam.gserviceaccount.com"
    scopes = ["https://www.googleapis.com/auth/compute.readonly"]
  }
}

# GCP CIS 5.2 — uniform_bucket_level_access = true
resource "google_storage_bucket" "bucket" {
  name                        = "my-secure-bucket"
  location                    = "US"
  uniform_bucket_level_access = true
}

# GCP CIS 2.4 — retention policy with bucket lock enabled
resource "google_storage_bucket" "good_log_bucket" {
  location                    = "US"
  name                        = "good-log-bucket"
  uniform_bucket_level_access = true

  retention_policy {
    is_locked        = true
    retention_period = 86400
  }
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
# GCP CIS 6.2.2 — log_connections = on
# GCP CIS 6.2.3 — log_disconnections = on
# GCP CIS 6.2.4 — log_statement = ddl
# GCP CIS 6.2.8 — cloudsql.enable_pgaudit = on
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

    database_flags {
      name  = "log_connections"
      value = "on"
    }

    database_flags {
      name  = "log_disconnections"
      value = "on"
    }

    database_flags {
      name  = "log_statement"
      value = "ddl"
    }

    database_flags {
      name  = "cloudsql.enable_pgaudit"
      value = "on"
    }
  }
}

# GCP CIS 6.1.1 — root user restricted to a specific host (not "%" or "")
# GCP CIS 6.1.2 — skip_show_database = on
# GCP CIS 6.1.3 — local_infile = off
resource "google_sql_database_instance" "good_mysql" {
  name             = "good-mysql"
  database_version = "MYSQL_8_0"

  settings {
    tier = "db-f1-micro"

    database_flags {
      name  = "local_infile"
      value = "off"
    }

    database_flags {
      name  = "skip_show_database"
      value = "on"
    }

    ip_configuration {
      ipv4_enabled = false
      ssl_mode     = "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"
    }

    backup_configuration {
      enabled = true
    }
  }
}

resource "google_sql_user" "good_root_user" {
  host     = "127.0.0.1"
  instance = "good-mysql"
  name     = "root"
}

# GCP CIS 7.1 — access granted to a specific user, not allUsers/allAuthenticatedUsers
# GCP CIS 7.3 — default_encryption_configuration with kms_key_name set
resource "google_bigquery_dataset" "good_dataset" {
  dataset_id = "good_dataset"

  access {
    role          = "READER"
    user_by_email = "someone@example.com"
  }

  default_encryption_configuration {
    kms_key_name = "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key"
  }
}

# GKE CIS 5.10.2 — enable_kubernetes_alpha absent (defaults to false)
# GKE CIS 5.10.4 — binary_authorization.evaluation_mode != DISABLED
# GKE CIS 5.6.1 — enable_intranode_visibility = true
# Note: 5.10.1 (kubernetes_dashboard) was removed from the Google provider;
#       the block is no longer valid and the dashboard is permanently disabled in GKE.
resource "google_container_cluster" "good_cluster" {
  name     = "good-cluster"
  location = "us-central1"

  enable_shielded_nodes       = true
  enable_legacy_abac          = false
  enable_intranode_visibility = true

  logging_service    = "logging.googleapis.com/kubernetes"
  monitoring_service = "monitoring.googleapis.com/kubernetes"

  networking_mode = local.networking_mode

  ip_allocation_policy {}

  release_channel {
    channel = var.release_channel
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
# GKE CIS 5.5.1 — image_type absent (GKE defaults to COS_CONTAINERD)
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
    boot_disk_kms_key = "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key"
    service_account   = "my-gke-sa@my-project.iam.gserviceaccount.com"

    sandbox_config {
      sandbox_type = "GVISOR"
    }

    shielded_instance_config {
      enable_integrity_monitoring = true
      enable_secure_boot          = true
    }

    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }
}

# GCP CIS 2.13 — DNS policy with logging enabled
resource "google_dns_policy" "good_dns_policy" {
  enable_logging = true
  name           = "good-dns-policy"
}

# GCP CIS 1.18 — v1 Cloud Function with non-sensitive environment variable keys
resource "google_cloudfunctions_function" "good_function" {
  name    = "good-function"
  runtime = "python39"

  environment_variables = {
    LOG_LEVEL = "INFO"
    REGION    = "us-central1"
  }
}

# GCP CIS 1.18 — v2 Cloud Function using Secret Manager for secrets (not env vars)
resource "google_cloudfunctions2_function" "good_function_v2" {
  location = "us-central1"
  name     = "good-function-v2"

  service_config {
    environment_variables = {
      LOG_LEVEL = "INFO"
    }

    secret_environment_variables {
      key        = "API_KEY"
      project_id = "my-project"
      secret     = "my-api-key-secret"
      version    = "latest"
    }
  }
}

# GKE CIS 5.6.7 — Ingress (kubernetes_manifest) with TLS and Google-managed cert annotation
resource "kubernetes_manifest" "good_ingress" {
  manifest = {
    apiVersion = "networking.k8s.io/v1"
    kind       = "Ingress"

    metadata = {
      annotations = {
        "networking.gke.io/managed-certificates" = "my-managed-cert"
      }

      name      = "good-ingress"
      namespace = "default"
    }

    spec = {
      tls = [
        {
          hosts = ["example.com"]
        }
      ]
    }
  }
}

# GKE CIS 5.6.7 — Ingress (kubernetes_ingress_v1) with TLS and Google-managed cert annotation
resource "kubernetes_ingress_v1" "good_ingress" {
  metadata {
    annotations = {
      "networking.gke.io/managed-certificates" = "my-managed-cert"
    }

    name      = "good-ingress"
    namespace = "default"
  }

  spec {
    tls {
      hosts       = ["example.com"]
      secret_name = "my-managed-cert-secret"
    }
  }
}

# GCP CIS 2.17 — backend service with logging enabled and non-zero sample rate
resource "google_compute_backend_service" "good_backend" {
  name = "good-backend"

  log_config {
    enable      = true
    sample_rate = 1
  }
}

# GCP CIS 2.1 — allServices audit config with all three log types and no exempted members
resource "google_project_iam_audit_config" "good_audit_config" {
  project = "my-project"
  service = "allServices"

  audit_log_config {
    log_type = "ADMIN_READ"
  }

  audit_log_config {
    log_type = "DATA_READ"
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

# GCP CIS 2.5 — log metric filter for project ownership changes
resource "google_logging_metric" "project_ownership_changes" {
  filter = "protoPayload.serviceData.policyDelta.bindingDeltas.role=\"roles/owner\""
  name   = "project_ownership_changes"
}

resource "google_monitoring_alert_policy" "project_ownership_changes_alert" {
  combiner     = "OR"
  display_name = "Project Ownership Changes"

  conditions {
    display_name = "Project Ownership Changes Condition"

    condition_threshold {
      comparison = "COMPARISON_GT"
      duration   = "0s"
      filter     = "metric.type=\"logging.googleapis.com/user/project_ownership_changes\" resource.type=\"global\""
    }
  }
}

# GCP CIS 2.6 — log metric filter for audit configuration changes
resource "google_logging_metric" "audit_config_changes" {
  filter = "protoPayload.methodName=\"SetIamPolicy\" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*"
  name   = "audit_config_changes"
}

resource "google_monitoring_alert_policy" "audit_config_changes_alert" {
  combiner     = "OR"
  display_name = "Audit Config Changes"

  conditions {
    display_name = "Audit Config Changes Condition"

    condition_threshold {
      comparison = "COMPARISON_GT"
      duration   = "0s"
      filter     = "metric.type=\"logging.googleapis.com/user/audit_config_changes\" resource.type=\"global\""
    }
  }
}

# GCP CIS 2.7 — log metric filter for custom role changes
resource "google_logging_metric" "custom_role_changes" {
  filter = "resource.type=\"iam_role\" AND protoPayload.methodName=\"google.iam.admin.v1.CreateRole\""
  name   = "custom_role_changes"
}

resource "google_monitoring_alert_policy" "custom_role_changes_alert" {
  combiner     = "OR"
  display_name = "Custom Role Changes"

  conditions {
    display_name = "Custom Role Changes Condition"

    condition_threshold {
      comparison = "COMPARISON_GT"
      duration   = "0s"
      filter     = "metric.type=\"logging.googleapis.com/user/custom_role_changes\" resource.type=\"global\""
    }
  }
}

# GCP CIS 2.8 — log metric filter for VPC firewall rule changes
resource "google_logging_metric" "firewall_rule_changes" {
  filter = "resource.type=\"gce_firewall_rule\" AND protoPayload.methodName:\"compute.firewalls.patch\""
  name   = "firewall_rule_changes"
}

resource "google_monitoring_alert_policy" "firewall_rule_changes_alert" {
  combiner     = "OR"
  display_name = "Firewall Rule Changes"

  conditions {
    display_name = "Firewall Rule Changes Condition"

    condition_threshold {
      comparison = "COMPARISON_GT"
      duration   = "0s"
      filter     = "metric.type=\"logging.googleapis.com/user/firewall_rule_changes\" resource.type=\"global\""
    }
  }
}

# GCP CIS 2.9 — log metric filter for VPC route changes
resource "google_logging_metric" "vpc_route_changes" {
  filter = "resource.type=\"gce_route\" AND protoPayload.methodName:\"compute.routes.delete\""
  name   = "vpc_route_changes"
}

resource "google_monitoring_alert_policy" "vpc_route_changes_alert" {
  combiner     = "OR"
  display_name = "VPC Route Changes"

  conditions {
    display_name = "VPC Route Changes Condition"

    condition_threshold {
      comparison = "COMPARISON_GT"
      duration   = "0s"
      filter     = "metric.type=\"logging.googleapis.com/user/vpc_route_changes\" resource.type=\"global\""
    }
  }
}

# GCP CIS 2.10 — log metric filter for VPC network changes
resource "google_logging_metric" "vpc_network_changes" {
  filter = "resource.type=\"gce_network\" AND protoPayload.methodName:\"compute.networks.insert\""
  name   = "vpc_network_changes"
}

resource "google_monitoring_alert_policy" "vpc_network_changes_alert" {
  combiner     = "OR"
  display_name = "VPC Network Changes"

  conditions {
    display_name = "VPC Network Changes Condition"

    condition_threshold {
      comparison = "COMPARISON_GT"
      duration   = "0s"
      filter     = "metric.type=\"logging.googleapis.com/user/vpc_network_changes\" resource.type=\"global\""
    }
  }
}

# GCP CIS 2.11 — log metric filter for Cloud Storage IAM permission changes
resource "google_logging_metric" "storage_iam_changes" {
  filter = "resource.type=\"gcs_bucket\" AND protoPayload.methodName=\"storage.setIamPermissions\""
  name   = "storage_iam_changes"
}

resource "google_monitoring_alert_policy" "storage_iam_changes_alert" {
  combiner     = "OR"
  display_name = "Storage IAM Changes"

  conditions {
    display_name = "Storage IAM Changes Condition"

    condition_threshold {
      comparison = "COMPARISON_GT"
      duration   = "0s"
      filter     = "metric.type=\"logging.googleapis.com/user/storage_iam_changes\" resource.type=\"global\""
    }
  }
}

# GCP CIS 2.12 — log metric filter for SQL instance configuration changes
resource "google_logging_metric" "sql_instance_changes" {
  filter = "protoPayload.methodName=\"cloudsql.instances.update\""
  name   = "sql_instance_changes"
}

resource "google_monitoring_alert_policy" "sql_instance_changes_alert" {
  combiner     = "OR"
  display_name = "SQL Instance Changes"

  conditions {
    display_name = "SQL Instance Changes Condition"

    condition_threshold {
      comparison = "COMPARISON_GT"
      duration   = "0s"
      filter     = "metric.type=\"logging.googleapis.com/user/sql_instance_changes\" resource.type=\"global\""
    }
  }
}

# GCP CIS 8.1 — Dataproc cluster with customer-managed encryption key
resource "google_dataproc_cluster" "good_dataproc" {
  name   = "good-dataproc"
  region = "us-central1"

  cluster_config {
    encryption_config {
      kms_key_name = "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key"
    }
  }
}
