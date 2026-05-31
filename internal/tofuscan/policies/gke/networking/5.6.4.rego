package tofuscan

import rego.v1

_desc_5_6_4 := concat("", [
	"Enabling a private endpoint and disabling public access to the GKE control plane ",
	"prevents direct internet access to the Kubernetes API server.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_cluster
	some resource in resources
	some pcc in object.get(resource, "private_cluster_config", [{}])
	object.get(pcc, "enable_private_endpoint", false) != true
	violation := {
		"resource": concat(".", ["google_container_cluster", name]),
		"rule_id": "gke/cis/5.6.4",
		"cis_control": "5.6.4",
		"profile_level": "Level 2",
		"severity": "High",
		"title": "Ensure Clusters Are Created with Private Endpoint Enabled and Public Access Disabled",
		"description": _desc_5_6_4,
	}
}
