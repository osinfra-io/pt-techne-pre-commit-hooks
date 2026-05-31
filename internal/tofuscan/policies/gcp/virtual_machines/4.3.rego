package tofuscan

import rego.v1

import data.tofuscan.lib

_desc_4_3 := concat("", [
	"Project-wide SSH keys are shared across all instances. Blocking them ensures ",
	"each instance uses only its own instance-level SSH keys, reducing the blast radius of a compromised key.",
])

deny contains violation if {
	some name, resources in input.resource.google_compute_instance
	some resource in resources
	metadata := object.get(resource, "metadata", {})
	not lib.truthy(object.get(metadata, "block-project-ssh-keys", false))
	not lib.truthy(object.get(metadata, "enable-oslogin", false))
	violation := {
		"resource": concat(".", ["google_compute_instance", name]),
		"rule_id": "gcp/cis/4.3",
		"cis_control": "4.3",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure Block Project-Wide SSH Keys Is Enabled for VM Instances",
		"description": _desc_4_3,
	}
}
