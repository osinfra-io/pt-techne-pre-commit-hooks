# CIS Google Kubernetes Engine (GKE) Benchmark v1.8.0

Controls extracted from the [CIS Google Kubernetes Engine (GKE) Benchmark
v1.8.0](https://www.cisecurity.org/benchmark/kubernetes).
`✅` = tofuscan policy implemented.

---

## Overview

The CIS GKE Benchmark provides prescriptive guidance for establishing a secure
baseline configuration for Google Kubernetes Engine clusters. It is a
specialization of the broader CIS Kubernetes Benchmark, tailored to the GKE
managed service and its GCP-specific features.

The benchmark is produced through a consensus review process involving global
security practitioners, cluster administrators, and cloud engineers. Controls
span worker node hardening, Kubernetes policy enforcement, and GKE-specific
managed service configuration.

**Intended audience:** cluster administrators, security specialists, auditors,
and personnel who develop, deploy, assess, or secure solutions built on GKE.

### Profile Levels

| Level | Description |
| ------- | ------------- |
| **Level 1** | Practical and prudent controls that provide a clear security benefit without inhibiting the utility of the technology beyond acceptable means. Suitable for all deployments. |
| **Level 2** | Extends Level 1. Intended for environments where security is more critical than ease of management. May impact cluster functionality or require additional configuration. |

---

## 3 Worker Nodes

This section consists of security recommendations for the components that run on
GKE worker nodes, covering configuration file permissions and ownership.

### 3.1 Worker Node Configuration Files

Controls covering permissions and ownership of kubeconfig and kubelet
configuration files on worker nodes. Correct permissions prevent unauthorized
modification of node configuration.

| Control | Title | Type | Covered | Description |
| --------- | ------- | ------ | --------- | ------------- |
| 3.1.1 | Ensure that the kubeconfig file permissions are set to 644 or more restrictive | Automated | | The kubelet kubeconfig file controls various parameters of the kubelet service. Permissions should be 644 or more restrictive to prevent unauthorized modification. |
| 3.1.2 | Ensure that the kubelet kubeconfig file ownership is set to root:root | Automated | | The kubelet kubeconfig file should be owned by root to prevent non-root processes from modifying the kubelet configuration. |
| 3.1.3 | Ensure that the kubelet configuration file has permissions set to 644 | Automated | | The kubelet configuration file may contain sensitive parameters. Permissions of 644 ensure only the root user can modify it. |
| 3.1.4 | Ensure that the kubelet configuration file ownership is set to root:root | Automated | | Kubelet configuration files should be owned by root to prevent tampering by other users or processes on the node. |

---

## 4 Policies

This section contains recommendations for various Kubernetes policies important
to the security of the cluster environment, covering RBAC, service accounts, pod
security, network policies, and secret management.

### 4.1 RBAC and Service Accounts

| Control | Title | Type | Covered | Description |
| --------- | ------- | ------ | --------- | ------------- |
| 4.1.1 | Ensure that the cluster-admin role is only used where required | Automated | | The `cluster-admin` ClusterRole grants unrestricted access to the entire cluster. It should be bound only to specific service accounts or users with a documented requirement. |
| 4.1.2 | Minimize access to secrets | Automated | | The Kubernetes API stores secrets including service account tokens. Access via `get`, `watch`, or `list` on secrets should be minimized to reduce credential exposure. |
| 4.1.3 | Minimize wildcard use in Roles and ClusterRoles | Automated | | Wildcard (`*`) resource or verb entries in RBAC roles grant overly broad permissions. Roles should enumerate only the specific resources and verbs needed. |
| 4.1.4 | Ensure that default service accounts are not actively used | Automated | | The default service account in each namespace is automatically bound to pods unless overridden. It should not have API access; use dedicated service accounts instead. |
| 4.1.5 | Ensure that Service Account Tokens are only mounted where necessary | Automated | | Auto-mounting service account tokens into pods that do not need API access increases the risk of token theft. Set `automountServiceAccountToken: false` where not required. |
| 4.1.6 | Avoid use of system:masters group | Automated | | The `system:masters` group bypasses RBAC entirely. No user or service account should be a member of this group in production clusters. |
| 4.1.7 | Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster | Automated | | The `bind`, `impersonate`, and `escalate` verbs allow privilege escalation beyond the principal's own permissions. These verbs must be tightly restricted. |
| 4.1.8 | Avoid bindings to system:anonymous | Automated | | Binding roles to `system:anonymous` grants permissions to unauthenticated requests. There is no legitimate use case for this in a production cluster. |
| 4.1.9 | Avoid non-default bindings to system:unauthenticated | Automated | | Non-default role bindings to `system:unauthenticated` extend unauthenticated access beyond Kubernetes defaults and should be removed. |
| 4.1.10 | Avoid non-default bindings to system:authenticated | Automated | | Bindings to `system:authenticated` grant permissions to every authenticated user in the cluster, which is typically far too broad. |

### 4.2 Pod Security Standards

| Control | Title | Type | Covered | Description |
| --------- | ------- | ------ | --------- | ------------- |
| 4.2.1 | Ensure that the cluster enforces Pod Security Standard Baseline profile or stricter for all namespaces | Manual | | The Pod Security Standard Baseline profile restricts known privilege escalation paths (e.g., host namespaces, hostPath volumes). All namespaces should enforce at least this profile. |

### 4.3 Network Policies and CNI

| Control | Title | Type | Covered | Description |
| --------- | ------- | ------ | --------- | ------------- |
| 4.3.1 | Ensure that the CNI in use supports Network Policies | Manual | | The Container Network Interface plugin must support Kubernetes NetworkPolicy so that pod-to-pod traffic can be restricted by policy. GKE uses Calico or Dataplane V2. |
| 4.3.2 | Ensure that all Namespaces have Network Policies defined | Automated | | Without NetworkPolicy, all pods in a namespace can communicate freely. Each namespace should have at least a default deny policy with explicit allow rules for required traffic. |

### 4.4 Secrets Management

| Control | Title | Type | Covered | Description |
| --------- | ------- | ------ | --------- | ------------- |
| 4.4.1 | Prefer using secrets as files over secrets as environment variables | Automated | | Secrets mounted as environment variables can be exposed through logs, `/proc` introspection, or child process inheritance. Mounting secrets as files limits their exposure. |
| 4.4.2 | Consider external secret storage | Manual | | Kubernetes secrets are base64-encoded in etcd, not encrypted by default. External secret stores (e.g., GCP Secret Manager, HashiCorp Vault) provide stronger access control and auditing. |

### 4.5 Extensible Admission Control

| Control | Title | Type | Covered | Description |
| --------- | ------- | ------ | --------- | ------------- |
| 4.5.1 | Configure Image Provenance using ImagePolicyWebhook admission controller | Manual | | An ImagePolicyWebhook enforces that only images from trusted registries are deployed, preventing execution of unverified or malicious container images. |

### 4.6 General Policies

| Control | Title | Type | Covered | Description |
| --------- | ------- | ------ | --------- | ------------- |
| 4.6.1 | Create administrative boundaries between resources using namespaces | Manual | | Kubernetes namespaces provide logical isolation between workloads. Separate teams and applications into dedicated namespaces to enforce RBAC and network policy boundaries. |
| 4.6.2 | Ensure that the seccomp profile is set to RuntimeDefault in the pod definitions | Automated | | The `RuntimeDefault` seccomp profile restricts the system calls available to containers to a safe subset, reducing the kernel attack surface. |
| 4.6.3 | Apply Security Context to Pods and Containers | Manual | | Security contexts define privilege and access control settings for pods and containers, such as `runAsNonRoot`, `readOnlyRootFilesystem`, and `allowPrivilegeEscalation: false`. |
| 4.6.4 | The default namespace should not be used | Automated | | Workloads in the `default` namespace are difficult to isolate with NetworkPolicy and RBAC. All production workloads should be deployed to dedicated namespaces. |

---

## 5 GKE-Specific Recommendations

This section consists of security recommendations for the direct configuration
of GKE managed service components. These controls are specifically applicable to
features that exist only within the GKE managed service, covering image
scanning, service accounts, encryption, node configuration, networking, logging,
authentication, and cluster-level settings.

### 5.1 Image Registry and Image Scanning

| Control | Title | Type | Covered | Description |
| --------- | ------- | ------ | --------- | ------------- |
| 5.1.1 | Ensure Image Vulnerability Scanning is enabled | Automated | | Enable container image vulnerability scanning (via Artifact Registry or GKE Security Posture) to detect known CVEs in container images before or after deployment. |
| 5.1.2 | Minimize user access to Container Image repositories | Manual | | Restrict write access to image repositories to only CI/CD pipelines and administrators, preventing unauthorized image pushes. |
| 5.1.3 | Minimize cluster access to read-only for Container Image repositories | Manual | | GKE node service accounts should have read-only access to container image repositories, following least-privilege for image pulls. |
| 5.1.4 | Ensure only trusted container images are used | Manual | | Deploy only images from trusted, verified registries. Use Binary Authorization to enforce image provenance policies at deployment time. |

### 5.2 Identity and Access Management

| Control | Title | Type | Covered | Description |
| --------- | ------- | ------ | --------- | ------------- |
| 5.2.1 | Ensure GKE clusters are not running using the Compute Engine default service account | Automated | ✅ | The Compute Engine default service account has the Editor role on the project. GKE nodes should use a dedicated, least-privilege service account. |
| 5.2.2 | Prefer using dedicated GCP Service Accounts and Workload Identity | Manual | | Workload Identity allows Kubernetes service accounts to act as GCP service accounts, eliminating the need to manage service account key files for pod-level GCP API access. |

### 5.3 Cloud KMS

| Control | Title | Type | Covered | Description |
| --------- | ------- | ------ | --------- | ------------- |
| 5.3.1 | Ensure Kubernetes Secrets are encrypted using keys managed in Cloud KMS | Automated | ✅ | By default, Kubernetes secrets are encrypted at rest using GCP-managed keys. Using application-layer encryption with Cloud KMS keys gives customers control over key rotation and revocation. |

### 5.4 Node Metadata

| Control | Title | Type | Covered | Description |
| --------- | ------- | ------ | --------- | ------------- |
| 5.4.1 | Ensure the GKE Metadata Server is Enabled | Automated | ✅ | The GKE Metadata Server blocks pod access to sensitive instance metadata (including legacy service account credentials) and is required for Workload Identity to function. |

### 5.5 Node Configuration and Maintenance

| Control | Title | Type | Covered | Description |
| --------- | ------- | ------ | --------- | ------------- |
| 5.5.1 | Ensure Container-Optimized OS (cos_containerd) is used for GKE node images | Automated | ✅ | Container-Optimized OS is a managed, hardened OS built for running containers. It has a minimal attack surface, read-only root filesystem, and automatic updates. |
| 5.5.2 | Ensure Node Auto-Repair is enabled for GKE nodes | Automated | ✅ | Node Auto-Repair monitors node health and automatically recreates unhealthy nodes, reducing the risk of workloads running on degraded or compromised nodes. |
| 5.5.3 | Ensure Node Auto-Upgrade is enabled for GKE nodes | Automated | ✅ | Auto-Upgrade keeps nodes running the latest Kubernetes version and OS patches, ensuring known vulnerabilities are addressed promptly. |
| 5.5.4 | When creating New Clusters - Automate GKE version management using Release Channels | Automated | ✅ | Enrolling clusters in a Release Channel (Rapid, Regular, or Stable) automates Kubernetes version upgrades within a tested, supported cadence. |
| 5.5.5 | Ensure Shielded GKE Nodes are Enabled | Automated | ✅ | Shielded GKE Nodes use Secure Boot, vTPM-enabled Measured Boot, and Integrity Monitoring to verify node integrity and detect boot-level compromise. |
| 5.5.6 | Ensure Integrity Monitoring for Shielded GKE Nodes is Enabled | Automated | ✅ | Integrity Monitoring uses vTPM measurements to detect changes to the node's boot sequence, alerting on deviations that may indicate tampering. |
| 5.5.7 | Ensure Secure Boot for Shielded GKE Nodes is Enabled | Automated | ✅ | Secure Boot verifies that only signed OS components are loaded during node startup, preventing boot-level rootkits and unsigned kernel modules. |

### 5.6 Cluster Networking

| Control | Title | Type | Covered | Description |
| --------- | ------- | ------ | --------- | ------------- |
| 5.6.1 | Enable VPC Flow Logs and Intranode Visibility | Automated | ✅ | Intranode visibility enables VPC Flow Logs to capture pod-to-pod traffic within a single node, providing complete network visibility for forensics and anomaly detection. |
| 5.6.2 | Ensure use of VPC-native clusters | Automated | ✅ | VPC-native clusters use Alias IPs for pod addresses, enabling pod-level VPC firewall rules and routing without requiring NAT or custom iptables rules. |
| 5.6.3 | Ensure Control Plane Authorized Networks is Enabled | Automated | ✅ | Authorized Networks restricts access to the GKE control plane API server to a specified allowlist of CIDR ranges, preventing unauthorized remote access. |
| 5.6.4 | Ensure clusters are created with Private Endpoint Enabled and Public Access Disabled | Automated | ✅ | Enabling a private endpoint and disabling public access ensures the GKE API server is only reachable from within the VPC, eliminating internet exposure. |
| 5.6.5 | Ensure clusters are created with Private Nodes | Automated | ✅ | Private Nodes have no public IP addresses, so they cannot be directly reached from the internet. Outbound internet access is provided via Cloud NAT. |
| 5.6.6 | Consider firewalling GKE worker nodes | Manual | | VPC firewall rules should restrict traffic to GKE worker nodes to only what is required for cluster operation, reducing the attack surface of node-level services. |
| 5.6.7 | Ensure use of Google-managed SSL Certificates | Automated | | Google-managed SSL certificates for GKE Ingress are automatically provisioned and renewed, eliminating the risk of certificate expiry and manual key management errors. |

### 5.7 Logging

| Control | Title | Type | Covered | Description |
| --------- | ------- | ------ | --------- | ------------- |
| 5.7.1 | Ensure Logging and Cloud Monitoring is Enabled | Automated | ✅ | GKE should export system and workload logs to Cloud Logging and metrics to Cloud Monitoring for centralized observability, alerting, and audit trail retention. |
| 5.7.2 | Enable Linux auditd logging | Manual | | Enabling `auditd` on GKE nodes captures system call activity including file access, process execution, and privilege escalation, providing host-level audit trails. |

### 5.8 Authentication and Authorization

| Control | Title | Type | Covered | Description |
| --------- | ------- | ------ | --------- | ------------- |
| 5.8.1 | Ensure authentication using Client Certificates is Disabled | Automated | ✅ | Client certificate authentication cannot be revoked and should be disabled in favor of OIDC or Google Groups-based authentication. |
| 5.8.2 | Manage Kubernetes RBAC users with Google Groups for GKE | Manual | | Binding GKE RBAC roles to Google Groups rather than individual identities simplifies access management and automatically revokes access when users leave the organization. |
| 5.8.3 | Ensure Legacy Authorization (ABAC) is Disabled | Automated | ✅ | Attribute-Based Access Control (ABAC) has been superseded by RBAC and is no longer actively maintained. Enabling ABAC bypasses RBAC and grants overly broad access. |

### 5.9 Storage

| Control | Title | Type | Covered | Description |
| --------- | ------- | ------ | --------- | ------------- |
| 5.9.1 | Enable Customer-Managed Encryption Keys (CMEK) for GKE Persistent Disks | Manual | | Encrypting GKE Persistent Disk volumes with CMEK gives organizations control over the encryption key lifecycle, enabling independent key revocation. |
| 5.9.2 | Enable Customer-Managed Encryption Keys (CMEK) for Boot Disks | Automated | | Encrypting GKE node boot disks with CMEK ensures node OS data is encrypted with customer-controlled keys, not just Google-managed defaults. |

### 5.10 Other Cluster Configurations

| Control | Title | Type | Covered | Description |
| --------- | ------- | ------ | --------- | ------------- |
| 5.10.1 | Ensure Kubernetes Web UI is Disabled | Automated | ✅ | The Kubernetes Dashboard provides a broad cluster management interface. It should be disabled in GKE as it is an additional attack vector and GCP Console provides equivalent functionality. |
| 5.10.2 | Ensure that Alpha clusters are not used for production workloads | Automated | ✅ | Alpha clusters enable experimental Kubernetes features but receive no SLA, security updates, or support guarantees. They must not be used for production workloads. |
| 5.10.3 | Consider GKE Sandbox for running untrusted workloads | Automated | | GKE Sandbox uses gVisor to provide an additional layer of isolation between the host kernel and containerized workloads, suitable for running untrusted or multi-tenant code. |
| 5.10.4 | Enable Security Posture | Manual | | GKE Security Posture provides continuous assessment of cluster configuration and workload security, surfacing actionable findings aligned with CIS and other benchmarks. |

---

## Coverage Summary

| Total Controls | Automated | Manual | Implemented |
| ---------------- | ----------- | -------- | ------------- |
| 58 | 43 | 15 | 20 |
