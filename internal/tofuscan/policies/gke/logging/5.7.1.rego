package tofuscan

import rego.v1

_desc_5_7_1_logging := concat("", [
	"Cloud Logging for GKE captures cluster activity, enabling security ",
	"auditing, alerting, and incident response.",
])

_desc_5_7_1_monitoring := concat("", [
	"Cloud Monitoring for GKE captures cluster performance metrics, enabling ",
	"alerting and incident response for availability and resource issues.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_cluster
	some resource in resources
	resource.logging_service == "none"
	violation := {
		"resource": concat(".", ["google_container_cluster", name]),
		"rule_id": "gke/cis/5.7.1",
		"cis_control": "5.7.1",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure Logging and Cloud Monitoring Is Enabled — Logging",
		"description": _desc_5_7_1_logging,
	}
}

deny contains violation if {
	some name, resources in input.resource.google_container_cluster
	some resource in resources
	resource.monitoring_service == "none"
	violation := {
		"resource": concat(".", ["google_container_cluster", name]),
		"rule_id": "gke/cis/5.7.1",
		"cis_control": "5.7.1",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure Logging and Cloud Monitoring Is Enabled — Monitoring",
		"description": _desc_5_7_1_monitoring,
	}
}
