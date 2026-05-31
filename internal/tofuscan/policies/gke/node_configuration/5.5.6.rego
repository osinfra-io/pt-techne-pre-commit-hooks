package tofuscan

import rego.v1

_desc_5_5_6 := concat("", [
	"Integrity Monitoring for Shielded GKE Nodes detects changes to the node boot ",
	"sequence by comparing measurements against a known-good baseline.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_node_pool
	some resource in resources
	some nc in object.get(resource, "node_config", [{}])
	some sic in object.get(nc, "shielded_instance_config", [{}])
	object.get(sic, "enable_integrity_monitoring", false) != true
	violation := {
		"resource": concat(".", ["google_container_node_pool", name]),
		"rule_id": "gke/cis/5.5.6",
		"cis_control": "5.5.6",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure Integrity Monitoring for Shielded GKE Nodes Is Enabled",
		"description": _desc_5_5_6,
	}
}
