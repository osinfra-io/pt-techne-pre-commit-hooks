package tofuscan

import rego.v1

_desc_4_5 := concat("", [
	"Serial console access allows interactive shell access outside the normal SSH path. ",
	"It should be disabled to eliminate an alternative attack vector.",
])

deny contains violation if {
	some name, resources in input.resource.google_compute_instance
	some resource in resources
	metadata := object.get(resource, "metadata", {})
	val := object.get(metadata, "serial-port-enable", "false")
	val == "true"
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/4.5",
		"cis_control": "4.5",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure 'Enable Connecting to Serial Ports' Is Not Enabled for VM Instance",
		"description": _desc_4_5,
	}
}

deny contains violation if {
	some name, resources in input.resource.google_compute_instance
	some resource in resources
	metadata := object.get(resource, "metadata", {})
	val := object.get(metadata, "serial-port-enable", "false")
	val == "1"
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/4.5",
		"cis_control": "4.5",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure 'Enable Connecting to Serial Ports' Is Not Enabled for VM Instance",
		"description": _desc_4_5,
	}
}

deny contains violation if {
	some name, resources in input.resource.google_compute_instance
	some resource in resources
	metadata := object.get(resource, "metadata", {})
	val := object.get(metadata, "serial-port-enable", false)
	val == true
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/4.5",
		"cis_control": "4.5",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure 'Enable Connecting to Serial Ports' Is Not Enabled for VM Instance",
		"description": _desc_4_5,
	}
}
