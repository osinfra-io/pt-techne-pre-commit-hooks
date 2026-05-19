package tofuscan

import rego.v1

_desc_5_8_3 := concat("", [
	"Legacy Authorization (ABAC) is a coarse-grained access control system that ",
	"should be disabled in favor of Role-Based Access Control (RBAC).",
])

deny contains violation if {
	some name, resources in input.resource.google_container_cluster
	some resource in resources
	resource.enable_legacy_abac == true
	violation := {
		"resource": name,
		"rule_id": "gke/cis/5.8.3",
		"cis_control": "5.8.3",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure Legacy Authorization (ABAC) Is Disabled",
		"description": _desc_5_8_3,
	}
}
