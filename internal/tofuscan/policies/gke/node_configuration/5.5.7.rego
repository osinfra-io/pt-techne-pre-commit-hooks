package tofuscan

import rego.v1

_desc_5_5_7 := concat("", [
	"Secure Boot for Shielded GKE Nodes ensures only authenticated OS software is ",
	"loaded at boot time, protecting against boot-level malware and rootkits.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_node_pool
	some resource in resources
	some nc in object.get(resource, "node_config", [{}])
	some sic in object.get(nc, "shielded_instance_config", [{}])
	object.get(sic, "enable_secure_boot", false) != true
	violation := {
		"resource": concat(".", ["google_container_node_pool", name]),
		"rule_id": "gke/cis/5.5.7",
		"cis_control": "5.5.7",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure Secure Boot for Shielded GKE Nodes Is Enabled",
		"description": _desc_5_5_7,
	}
}
