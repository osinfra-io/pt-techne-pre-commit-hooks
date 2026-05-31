package tofuscan

import rego.v1

import data.tofuscan.lib

_desc_5_5_5 := concat("", [
	"Shielded GKE Nodes provide verifiable node identity and integrity using ",
	"Secure Boot, vTPM, and Integrity Monitoring to defend against rootkits and bootkits.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_cluster
	some resource in resources

	# enable_shielded_nodes defaults to true on GKE, so absence is compliant; only
	# an explicit false is a violation. Skip values supplied by module outputs.
	value := object.get(resource, "enable_shielded_nodes", true)
	not lib.is_unresolved(value)
	value != true
	violation := {
		"resource": concat(".", ["google_container_cluster", name]),
		"rule_id": "gke/cis/5.5.5",
		"cis_control": "5.5.5",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure Shielded GKE Nodes Are Enabled",
		"description": _desc_5_5_5,
	}
}
