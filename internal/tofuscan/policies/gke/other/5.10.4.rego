package regofu

import rego.v1

_desc_5_10_4 := concat("", [
	"Binary Authorization enforces deploy-time security controls by requiring container ",
	"images to be signed and attested before they can run in GKE clusters.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_cluster
	some resource in resources
	object.get(resource, "enable_binary_authorization", false) != true
	ba_arr := object.get(resource, "binary_authorization", [{}])
	every ba in ba_arr {
		object.get(ba, "evaluation_mode", "DISABLED") == "DISABLED"
	}
	violation := {
		"resource": name,
		"rule_id": "gke/cis/5.10.4",
		"cis_control": "5.10.4",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure Use of Binary Authorization",
		"description": _desc_5_10_4,
	}
}
