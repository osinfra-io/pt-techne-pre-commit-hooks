package regofu

import rego.v1

_desc_5_5_4 := concat("", [
	"Release channels (RAPID, REGULAR, or STABLE) automate GKE version management, ",
	"ensuring clusters receive timely security patches and Kubernetes upgrades.",
])

_valid_channels := {"RAPID", "REGULAR", "STABLE"}

deny contains violation if {
	some name, resources in input.resource.google_container_cluster
	some resource in resources
	some rc in object.get(resource, "release_channel", [{}])
	channel := object.get(rc, "channel", "UNSPECIFIED")
	not channel in _valid_channels
	violation := {
		"resource": name,
		"rule_id": "gke/cis/5.5.4",
		"cis_control": "5.5.4",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure GKE Version Management Uses Release Channels",
		"description": _desc_5_5_4,
	}
}
