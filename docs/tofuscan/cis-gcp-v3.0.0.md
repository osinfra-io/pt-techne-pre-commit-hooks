# CIS Google Cloud Platform Foundation Benchmark v3.0.0

Controls extracted from the [CIS Google Cloud Platform Foundation Benchmark
v3.0.0](https://www.cisecurity.org/benchmark/google_cloud_computing_platform),
published 2024-03-29.
`✅` = tofuscan policy implemented.

---

## Overview

The CIS Google Cloud Platform Foundation Benchmark provides prescriptive
guidance for establishing a secure baseline configuration for Google Cloud
Platform (GCP) environments. It is produced through a consensus review process
involving a global community of security practitioners, auditors, and cloud
engineers.

The benchmark covers foundational security controls at the individual project
level across identity, logging, networking, compute, storage, databases,
analytics, and data processing services.

**Intended audience:** system and application administrators, security
specialists, auditors, DevOps engineers, and personnel who develop, deploy, or
secure solutions on GCP.

### Profile Levels

| Level | Description |
| ------- | ------------- |
| **Level 1** | Practical and prudent controls that provide a clear security benefit without significantly inhibiting usability. Suitable for most environments. |
| **Level 2** | Extends Level 1 for environments where security takes priority over manageability. May impact utility or performance, and may require additional licensing or third-party software. |

---

## 1 Identity and Access Management

This section covers recommendations addressing Identity and Access Management on
Google Cloud Platform. Controls focus on securing service accounts, enforcing
least-privilege IAM roles, managing cryptographic keys, and protecting API
credentials.

| Control | Level | Title | Type | Covered | Description |
| --------- | ------- | ------- | ------ | --------- | ------------- |
| 1.1 | Level 1 | Ensure that Corporate Login Credentials are Used | Manual | | Use corporate login credentials instead of consumer accounts such as Gmail accounts, ensuring visibility and auditing over access. |
| 1.2 | Level 1 | Ensure that Multi-Factor Authentication is Enabled for All Non-Service Accounts | Manual | | Require MFA for all user accounts to protect against credential compromise. |
| 1.3 | Level 1 | Ensure that Security Key Enforcement is Enabled for All Admin Accounts | Manual | | Require phishing-resistant hardware security keys for all admin accounts. |
| 1.4 | Level 1 | Ensure That There Are Only GCP-Managed Service Account Keys for Each Service Account | Automated | | User-managed service account keys are difficult to rotate and audit; only GCP-managed keys should be used. |
| 1.5 | Level 1 | Ensure That Service Account Has No Admin Privileges | Automated | ✅ | Service accounts should use the minimum necessary permissions; admin roles grant overly broad access to all GCP services. |
| 1.6 | Level 1 | Ensure That IAM Users Are Not Assigned the Service Account User or Service Account Token Creator Roles at Project Level | Automated | ✅ | Assign the `serviceAccountUser` and `serviceAccountTokenCreator` roles at the service account level, not the project level, to limit blast radius. |
| 1.7 | Level 1 | Ensure User-Managed/External Keys for Service Accounts Are Rotated Every 90 Days or Fewer | Automated | ✅ | Service Account keys used to authenticate API requests must be rotated regularly to limit exposure from key compromise. |
| 1.8 | Level 2 | Ensure That Separation of Duties Is Enforced While Assigning Service Account Related Roles to Users | Automated | | No user should hold both `Service Account Admin` and `Service Account User` roles simultaneously to prevent privilege escalation. |
| 1.9 | Level 1 | Ensure That Cloud KMS Cryptokeys Are Not Anonymously or Publicly Accessible | Automated | ✅ | KMS cryptokeys must restrict IAM policies to prevent `allUsers` or `allAuthenticatedUsers` from accessing encryption keys. |
| 1.10 | Level 1 | Ensure KMS Encryption Keys Are Rotated Within a Period of 90 Days | Automated | ✅ | KMS keys should be rotated at least every 90 days. Rotation limits the data exposed if a key is compromised and is controlled via a rotation schedule on each CryptoKey. |
| 1.11 | Level 2 | Ensure That Separation of Duties Is Enforced While Assigning KMS Related Roles to Users | Automated | | The principle of separation of duties requires that no single user holds both `Cloud KMS Admin` and any of the CryptoKey encrypter/decrypter roles. |
| 1.12 | Level 2 | Ensure API Keys Only Exist for Active Services | Automated | | Unused API keys with intact permissions pose a security risk. Keys for inactive services should be deleted to reduce attack surface. |
| 1.13 | Level 2 | Ensure API Keys Are Restricted To Use by Only Specified Hosts and Apps | Manual | | API keys should be restricted to specific HTTP referrers or IP addresses to limit misuse if a key is exposed. |
| 1.14 | Level 2 | Ensure API Keys Are Restricted to Only APIs That Application Needs Access | Automated | | API keys should be scoped to only the APIs the application actually uses. Unrestricted keys can be exploited to access any GCP service. |
| 1.15 | Level 2 | Ensure API Keys Are Rotated Every 90 Days | Automated | | If API keys must be used, rotate them every 90 days to limit the exposure window from a compromised key. |
| 1.16 | Level 1 | Ensure Essential Contacts is Configured for Organization | Automated | | Configure Essential Contacts with designated email addresses so GCP can deliver important security and operational notifications. |
| 1.17 | Level 1 | Ensure Secrets are Not Stored in Cloud Functions Environment Variables | Automated | | Cloud Functions environment variables are not encrypted and visible in the GCP console. Store secrets in Secret Manager instead. |

---

## 2 Logging and Monitoring

This section covers recommendations addressing Logging and Monitoring on Google
Cloud Platform. Controls ensure that audit logs are properly configured,
exported to durable sinks, and that metric-based alerts exist for high-impact
configuration changes including IAM, networking, and database modifications.

| Control | Level | Title | Type | Covered | Description |
| --------- | ------- | ------- | ------ | --------- | ------------- |
| 2.1 | Level 2 | Ensure That Cloud Audit Logging Is Configured Properly | Automated | | Cloud Audit Logs record admin activity and data access events across GCP services. Both Admin Activity and Data Access audit logs should be enabled for all services. |
| 2.2 | Level 1 | Ensure That Sinks Are Configured for All Log Entries | Automated | ✅ | A log sink exports copies of all log entries to a durable destination (Cloud Storage, BigQuery, Pub/Sub) enabling long-term retention and SIEM integration. |
| 2.3 | Level 1 | Ensure That Retention Policies on Cloud Storage Buckets Used for Exporting Logs Are Configured Using Bucket Lock | Automated | | Retention policies with Bucket Lock prevent log data from being modified or deleted before the retention period expires, protecting audit trails from tampering. |
| 2.4 | Level 2 | Ensure Log Metric Filter and Alerts Exist for Project Ownership Assignments/Changes | Automated | | Project ownership grants the highest privilege level. Metric filters and alerts on ownership assignment changes detect unauthorized privilege escalation. |
| 2.5 | Level 1 | Ensure That the Log Metric Filter and Alerts Exist for Audit Configuration Changes | Automated | | Changes to audit configuration could disable logging for critical events. Alerting on these changes helps detect attempts to cover tracks. |
| 2.6 | Level 1 | Ensure That the Log Metric Filter and Alerts Exist for Custom Role Changes | Automated | | Custom IAM roles can be modified to include broader permissions. Monitoring changes to custom roles detects unauthorized privilege expansion. |
| 2.7 | Level 2 | Ensure That the Log Metric Filter and Alerts Exist for VPC Network Firewall Rule Changes | Automated | | VPC firewall rule changes can open unintended network access. Metric filters and alerts provide visibility into firewall configuration drift. |
| 2.8 | Level 2 | Ensure That the Log Metric Filter and Alerts Exist for VPC Network Route Changes | Automated | | Route changes can redirect traffic to malicious destinations. A metric filter and alarm should be established for VPC network route changes. |
| 2.9 | Level 2 | Ensure That the Log Metric Filter and Alerts Exist for VPC Network Changes | Automated | | Changes to VPC networks, such as peer connections or subnet modifications, can alter the network security boundary and should be alerted on. |
| 2.10 | Level 2 | Ensure That the Log Metric Filter and Alerts Exist for Cloud Storage IAM Permission Changes | Automated | | IAM permission changes on Cloud Storage buckets can expose sensitive data. Monitoring these changes enables early detection of unauthorized access grants. |
| 2.11 | Level 2 | Ensure That the Log Metric Filter and Alerts Exist for SQL Instance Configuration Changes | Automated | | SQL instance configuration changes (e.g., disabling SSL, enabling public IPs) can weaken database security and should trigger alerts. |
| 2.12 | Level 1 | Ensure That Cloud DNS Logging Is Enabled for All VPC Networks | Automated | | Cloud DNS logs record DNS queries made from within VPC networks to Stackdriver, providing visibility into potentially malicious DNS activity. |
| 2.13 | Level 1 | Ensure Cloud Asset Inventory Is Enabled | Automated | | Cloud Asset Inventory provides a time-series record of GCP resource metadata and IAM policies, enabling change tracking and compliance auditing. |
| 2.14 | Level 2 | Ensure Access Transparency is Enabled | Manual | | Access Transparency provides audit logs of actions taken by Google personnel on customer resources, improving accountability for support interactions. |
| 2.15 | Level 2 | Ensure Access Approval is Enabled | Automated | | Access Approval requires explicit customer approval before Google support can access project resources, adding an additional control over privileged access. |
| 2.16 | Level 2 | Ensure Logging is Enabled for HTTP(S) Load Balancer | Automated | | Enabling logging on HTTPS Load Balancers captures all network traffic and destinations, providing visibility into request patterns and potential attacks. |

---

## 3 Networking

This section covers recommendations addressing networking on Google Cloud
Platform. Controls focus on eliminating insecure defaults (default networks,
legacy networks), securing DNS with DNSSEC, restricting internet-exposed
firewall rules, enabling VPC Flow Logs, and enforcing strong TLS policies.

| Control | Level | Title | Type | Covered | Description |
| --------- | ------- | ------- | ------ | --------- | ------------- |
| 3.1 | Level 1 | Ensure That the Default Network Does Not Exist in a Project | Automated | ✅ | The default network is automatically created with permissive firewall rules. Projects should use custom VPC networks with explicitly defined rules instead. |
| 3.2 | Level 1 | Ensure Legacy Networks Do Not Exist for Older Projects | Automated | | Legacy networks lack subnet support and modern features. Projects must not use legacy network configurations, which are being phased out by Google. |
| 3.3 | Level 1 | Ensure That DNSSEC Is Enabled for Cloud DNS | Automated | ✅ | DNSSEC prevents DNS spoofing and cache poisoning by cryptographically signing DNS records, ensuring resolvers receive authentic responses. |
| 3.4 | Level 1 | Ensure That RSASHA1 Is Not Used for the Key-Signing Key in Cloud DNS DNSSEC | Automated | ✅ | RSASHA1 is a weak algorithm for DNSSEC key signing. SHA-1 has known weaknesses; use RSASHA256 or ECDSAP256SHA256 instead. |
| 3.5 | Level 1 | Ensure That RSASHA1 Is Not Used for the Zone-Signing Key in Cloud DNS DNSSEC | Automated | ✅ | The zone-signing key should not use RSASHA1 for the same reasons as the key-signing key — SHA-1 provides insufficient collision resistance. |
| 3.6 | Level 1 | Ensure That SSH Access Is Restricted From the Internet | Automated | ✅ | Firewall rules must not allow unrestricted inbound SSH (port 22) from `0.0.0.0/0` or `::/0`. Expose SSH only through IAP or a bastion host. |
| 3.7 | Level 2 | Ensure That RDP Access Is Restricted From the Internet | Automated | ✅ | Firewall rules must not allow unrestricted inbound RDP (port 3389) from `0.0.0.0/0` or `::/0`. Expose RDP only through IAP or a bastion host. |
| 3.8 | Level 2 | Ensure that VPC Flow Logs is Enabled for Every Subnet in a VPC Network | Automated | ✅ | VPC Flow Logs capture metadata about IP traffic on network interfaces, enabling network forensics, anomaly detection, and security auditing. |
| 3.9 | Level 1 | Ensure No HTTPS or SSL Proxy Load Balancers Permit SSL Policies With Weak Cipher Suites | Automated | ✅ | SSL policies control which TLS versions and cipher suites clients may use. Weak cipher suites should be explicitly excluded to prevent downgrade attacks. |
| 3.10 | | Use Identity Aware Proxy (IAP) to Ensure Only Traffic From Google IP Addresses are Allowed | Manual | | IAP authenticates user requests via Google SSO. Combine IAP with firewall rules that only allow traffic from Google's IP ranges for defence-in-depth. |

---

## 4 Virtual Machines

This section covers recommendations addressing virtual machines on Google Cloud
Platform. Controls reduce the attack surface of Compute Engine instances by
enforcing minimal service account permissions, disabling risky features (serial
ports, IP forwarding, public IPs), and requiring Shielded VM and Confidential
Computing configurations.

| Control | Level | Title | Type | Covered | Description |
| --------- | ------- | ------- | ------ | --------- | ------------- |
| 4.1 | Level 1 | Ensure That Instances Are Not Configured To Use the Default Service Account | Automated | ✅ | The default Compute Engine service account has the Editor role on the project. Instances should use a dedicated, least-privilege service account instead. |
| 4.2 | Level 1 | Ensure That Instances Are Not Configured To Use the Default Service Account With Full Access to All Cloud APIs | Automated | ✅ | Even if the default service account is used, granting full access to all Cloud APIs is excessively permissive and should be avoided. |
| 4.3 | Level 1 | Ensure Block Project-Wide SSH Keys Is Enabled for VM Instances | Automated | ✅ | Project-wide SSH keys are shared across all instances. Blocking them ensures each instance uses only its own instance-level SSH keys, reducing the blast radius of a compromised key. |
| 4.4 | Level 1 | Ensure OS Login Is Enabled for a Project | Automated | ✅ | OS Login binds SSH certificates to IAM identities, enabling centralized SSH access management and automatic revocation when a user is removed from IAM. |
| 4.5 | Level 1 | Ensure Enable Connecting to Serial Ports Is Not Enabled for VM Instances | Automated | ✅ | Serial console access allows interactive shell access outside the normal SSH path. It should be disabled to eliminate an alternative attack vector. |
| 4.6 | Level 1 | Ensure That IP Forwarding Is Not Enabled on Instances | Automated | ✅ | IP forwarding allows an instance to forward packets addressed to other hosts. Unless the instance is functioning as a network appliance, this capability should be disabled. |
| 4.7 | Level 2 | Ensure VM Disks for Critical VMs Are Encrypted With Customer-Supplied Encryption Keys | Automated | ✅ | Customer-Supplied Encryption Keys (CSEK) give organizations full control over the encryption key lifecycle. If Google is compelled to provide data, it remains protected. |
| 4.8 | Level 2 | Ensure Compute Instances Are Launched With Shielded VM Enabled | Automated | ✅ | Shielded VMs use Secure Boot, vTPM-enabled measured boot, and integrity monitoring to defend against boot-level and firmware-level attacks. |
| 4.9 | Level 2 | Ensure That Compute Instances Do Not Have Public IP Addresses | Automated | ✅ | Instances with public IP addresses are directly reachable from the internet. Use Cloud NAT or a bastion host for outbound access and IAP for inbound management. |
| 4.10 | Level 2 | Ensure That App Engine Applications Enforce HTTPS Connections | Manual | | App Engine applications should redirect all HTTP traffic to HTTPS to ensure data is encrypted in transit. |
| 4.11 | Level 2 | Ensure That Compute Instances Have Confidential Computing Enabled | Automated | ✅ | Confidential Computing encrypts data in-use — while it is being processed in memory — using AMD SEV, preventing the hypervisor or Google from reading VM memory. |
| 4.12 | Level 2 | Ensure the Latest Operating System Updates Are Installed On Your Virtual Machines | Manual | | GCP OS Config can report patch compliance and apply OS patches. Keeping VMs patched reduces the risk of exploitation via known vulnerabilities. |

---

## 5 Storage

This section covers recommendations addressing storage on Google Cloud Platform.
Controls ensure Cloud Storage buckets are not publicly accessible and that
uniform IAM policies are applied consistently.

| Control | Level | Title | Type | Covered | Description |
| --------- | ------- | ------- | ------ | --------- | ------------- |
| 5.1 | Level 1 | Ensure That Cloud Storage Bucket Is Not Anonymously or Publicly Accessible | Automated | ✅ | IAM policies on Cloud Storage buckets must not grant access to `allUsers` or `allAuthenticatedUsers`, which would expose bucket contents to the public internet. |
| 5.2 | Level 2 | Ensure That Cloud Storage Buckets Have Uniform Bucket-Level Access Enabled | Automated | ✅ | Uniform bucket-level access disables per-object ACLs and enforces IAM-only access control, preventing inconsistent permissions that could inadvertently expose objects. |

---

## 6 Cloud SQL

This section covers security recommendations for Cloud SQL database services
across MySQL, PostgreSQL, and SQL Server engines. Controls address SSL
enforcement, public IP exposure, automated backups, and database flag hardening
to prevent unauthorized access and data loss.

| Control | Level | Title | Type | Covered | Description |
| --------- | ------- | ------- | ------ | --------- | ------------- |
| 6.1.1 | | Ensure That a MySQL Database Instance Does Not Allow Anyone To Connect With Administrative Privileges | Automated | | The MySQL root account should be configured with a strong password and restricted to localhost, preventing unauthorized administrative access. |
| 6.1.2 | | Ensure Skip_show_database Database Flag for Cloud SQL MySQL Instance Is Set to On | Automated | ✅ | Setting `skip_show_database=on` prevents users from using `SHOW DATABASES` unless they have the `SHOW DATABASES` privilege, reducing information disclosure. |
| 6.1.3 | | Ensure That the Local_infile Database Flag for a Cloud SQL MySQL Instance Is Set to Off | Automated | ✅ | The `local_infile` flag enables loading data from client-side files, which can be exploited to read arbitrary files on the client system. It should be disabled. |
| 6.2.1 | | Ensure Log_error_verbosity Database Flag for Cloud SQL PostgreSQL Instance Is Set to Default or Stricter | Automated | ✅ | Controls the verbosity of error messages logged by PostgreSQL. Overly verbose error logging can expose sensitive internal state. |
| 6.2.2 | | Ensure That the Log_connections Database Flag for Cloud SQL PostgreSQL Instance Is Set to On | Automated | ✅ | Enabling `log_connections` logs each successful connection to the database server, supporting audit trails for access monitoring. |
| 6.2.3 | | Ensure That the Log_disconnections Database Flag for Cloud SQL PostgreSQL Instance Is Set to On | Automated | ✅ | Enabling `log_disconnections` logs session termination details, providing a complete picture of database session activity alongside `log_connections`. |
| 6.2.4 | | Ensure Log_statement Database Flag for Cloud SQL PostgreSQL Instance Is Set Appropriately | Automated | ✅ | The `log_statement` flag controls which SQL statements are logged. It should be set to `ddl` or stricter to capture schema-level changes. |
| 6.2.5 | | Ensure that the Log_min_messages Flag for a Cloud SQL PostgreSQL Instance Is Set to Warning or Stricter | Automated | ✅ | Setting `log_min_messages` to `WARNING` or stricter ensures that only meaningful diagnostic messages are logged, balancing observability with log volume. |
| 6.2.6 | | Ensure Log_min_error_statement Database Flag for Cloud SQL PostgreSQL Instance Is Set to Error or Stricter | Automated | ✅ | Controls the minimum severity level for logging the SQL statement that caused a logged error, helping correlate errors with the queries that triggered them. |
| 6.2.7 | | Ensure That the Log_min_duration_statement Database Flag for Cloud SQL PostgreSQL Instance Is Set to -1 | Automated | ✅ | Setting `log_min_duration_statement=-1` disables logging of statement durations, preventing unintentional inclusion of query data (including literals) in logs. |
| 6.2.8 | | Ensure That cloudsql.enable_pgaudit Database Flag for each Cloud SQL PostgreSQL Instance Is Set to On | Automated | ✅ | The `pgaudit` extension provides detailed session and object audit logging required for compliance with standards like PCI DSS and HIPAA. |
| 6.3.1 | | Ensure external scripts enabled Database Flag for Cloud SQL SQL Server Instance Is Set to Off | Automated | ✅ | Disabling `external scripts enabled` prevents execution of scripts in external languages (e.g., Python, R) which can be exploited for code execution. |
| 6.3.2 | | Ensure That the cross db ownership chaining Database Flag for Cloud SQL SQL Server Instance Is Set to Off | Automated | ✅ | Cross-database ownership chaining can allow users to access objects in other databases. It should be disabled unless explicitly required. |
| 6.3.3 | | Ensure user Connections Database Flag for Cloud SQL SQL Server Instance Is Set to a Non-limiting Value | Automated | | The `user connections` flag should be set to 0 (unlimited) to prevent denial of service from connection limits while still allowing monitoring. |
| 6.3.4 | | Ensure user options Database Flag for Cloud SQL SQL Server Instance Is Not Configured | Automated | | The `user options` flag sets global defaults for all user sessions, which can override per-session settings and create unpredictable behavior. |
| 6.3.5 | | Ensure remote access Database Flag for Cloud SQL SQL Server Instance Is Set to Off | Automated | ✅ | Disabling remote access prevents the SQL Server instance from executing stored procedures on remote servers, reducing the attack surface. |
| 6.3.6 | | Ensure 3625 (trace flag) Database Flag for all Cloud SQL Server Instances Is Set to On | Automated | ✅ | Trace flag 3625 masks error message details shown to non-admin users, preventing information disclosure of internal SQL Server state. |
| 6.3.7 | | Ensure That the contained database authentication Database Flag for Cloud SQL SQL Server Instance Is Set to Off | Automated | ✅ | Contained databases can authenticate users without domain-level credentials, which can bypass organizational authentication policies. |
| 6.4 | Level 1 | Ensure That the Cloud SQL Database Instance Requires All Incoming Connections To Use SSL | Automated | ✅ | All connections to Cloud SQL must be encrypted using SSL/TLS to protect data in transit from eavesdropping and man-in-the-middle attacks. |
| 6.5 | Level 1 | Ensure That Cloud SQL Database Instances Do Not Implicitly Whitelist All Public IP Addresses | Automated | ✅ | Authorized Networks for Cloud SQL should not include `0.0.0.0/0`, which would allow connections from any IP address on the internet. |
| 6.6 | Level 2 | Ensure That Cloud SQL Database Instances Do Not Have Public IPs | Automated | ✅ | Cloud SQL instances should use private IP addresses only, accessible within a VPC network, to avoid direct internet exposure. |
| 6.7 | Level 1 | Ensure That Cloud SQL Database Instances Are Configured With Automated Backups | Automated | ✅ | Automated backups ensure that a recovery point is available in the event of data loss, corruption, or accidental deletion. |

---

## 7 BigQuery

This section addresses Google Cloud Platform BigQuery — a serverless, highly
scalable, cost-effective cloud data warehouse. Controls focus on preventing
public dataset access and ensuring data is encrypted with customer-managed keys.

| Control | Level | Title | Type | Covered | Description |
| --------- | ------- | ------- | ------ | --------- | ------------- |
| 7.1 | Level 1 | Ensure That BigQuery Datasets Are Not Anonymously or Publicly Accessible | Automated | ✅ | BigQuery dataset IAM policies must not include `allUsers` or `allAuthenticatedUsers`, which would expose potentially sensitive analytical data to the public. |
| 7.2 | Level 2 | Ensure That All BigQuery Tables Are Encrypted With Customer-Managed Encryption Key | Automated | ✅ | BigQuery uses Google-managed keys by default. Using Customer-Managed Encryption Keys (CMEK) gives organizations control over key rotation and revocation. |
| 7.3 | Level 2 | Ensure That a Default Customer-Managed Encryption Key Is Specified for All BigQuery Data Sets | Automated | ✅ | Setting a default CMEK on BigQuery datasets ensures all newly created tables are automatically encrypted with the organization's own keys. |
| 7.4 | Level 2 | Ensure all data in BigQuery has been classified | Manual | | Use Google Cloud's Sensitive Data Protection (formerly DLP) to discover, monitor, and classify sensitive data in BigQuery tables for appropriate handling. |

---

## 8 Dataproc

This section covers security recommendations for Dataproc, GCP's managed Spark
and Hadoop service. Cluster and job data is stored on Persistent Disks and Cloud
Storage; encrypting this data with customer-managed keys protects it from
unauthorized access.

| Control | Level | Title | Type | Covered | Description |
| --------- | ------- | ------- | ------ | --------- | ------------- |
| 8.1 | Level 2 | Ensure that Dataproc Cluster is Encrypted Using Customer-Managed Encryption Key | Automated | | Dataproc cluster data on Persistent Disks should be encrypted with CMEK so that the organization controls the key lifecycle and can revoke access independently of GCP. |

---

## Coverage Summary

| Total Controls | Automated | Manual | Implemented |
| ---------------- | ----------- | -------- | ------------- |
| 63 | 52 | 11 | 49 |
