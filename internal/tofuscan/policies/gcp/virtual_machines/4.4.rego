package regofu

import rego.v1

_desc_4_4 := concat("", [
	"OS Login binds SSH access to IAM identity, enabling centralized access management ",
	"and automatic revocation when a user is removed from IAM. It should be enabled on ",
	"all VM instances to replace unmanaged SSH key pairs.",
])

deny contains violation if {
	some name, resources in input.resource.google_compute_instance
	some resource in resources
	metadata := object.get(resource, "metadata", {})
	object.get(metadata, "enable-oslogin", "false") != "true"
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/4.4",
		"cis_control": "4.4",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure OS Login Is Enabled for a Project",
		"description": _desc_4_4,
	}
}
