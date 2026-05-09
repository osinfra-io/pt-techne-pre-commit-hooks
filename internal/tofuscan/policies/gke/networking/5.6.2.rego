package regofu

import rego.v1

_desc_5_6_2 := concat("", [
	"VPC-native clusters use alias IP ranges, enabling direct pod-to-pod routing, ",
	"improved network performance, and better integration with GCP networking features.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_cluster
	some resource in resources
	object.get(resource, "networking_mode", "ROUTES") != "VPC_NATIVE"
	violation := {
		"resource": name,
		"rule_id": "gke/cis/5.6.2",
		"cis_control": "5.6.2",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure Use of VPC-Native Clusters",
		"description": _desc_5_6_2,
	}
}
