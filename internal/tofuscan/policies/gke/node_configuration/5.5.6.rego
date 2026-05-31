package tofuscan

import rego.v1

import data.tofuscan.lib

_desc_5_5_6 := concat("", [
	"Integrity Monitoring for Shielded GKE Nodes detects changes to the node boot ",
	"sequence by comparing measurements against a known-good baseline.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_node_pool
	some resource in resources
	some nc in object.get(resource, "node_config", [{}])

	# Integrity monitoring defaults to enabled, so an absent shielded_instance_config
	# block (fallback []) and an absent enable_integrity_monitoring attribute
	# (default true) are both compliant; only an explicit false is a violation.
	some sic in object.get(nc, "shielded_instance_config", [])
	value := object.get(sic, "enable_integrity_monitoring", true)
	not lib.is_unresolved(value)
	value != true
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
