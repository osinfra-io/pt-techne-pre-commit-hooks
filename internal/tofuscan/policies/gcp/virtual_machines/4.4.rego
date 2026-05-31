package tofuscan

import rego.v1

import data.tofuscan.lib

_desc_4_4 := concat("", [
	"OS Login binds SSH access to IAM identity, enabling centralized access management ",
	"and automatic revocation when a user is removed from IAM. It should be enabled on ",
	"all VM instances to replace unmanaged SSH key pairs.",
])

deny contains violation if {
	some name, resources in input.resource.google_compute_instance
	some resource in resources
	not _oslogin_effective(resource)
	violation := {
		"resource": concat(".", ["google_compute_instance", name]),
		"rule_id": "gcp/cis/4.4",
		"cis_control": "4.4",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure OS Login Is Enabled for a Project",
		"description": _desc_4_4,
	}
}

# Instance-level metadata takes precedence; a boolean true or the strings
# "true"/"TRUE" are all valid.
_oslogin_effective(resource) if {
	metadata := object.get(resource, "metadata", {})
	lib.truthy(object.get(metadata, "enable-oslogin", false))
}

# Fall back to project-level metadata when the instance does not set the key.
_oslogin_effective(resource) if {
	metadata := object.get(resource, "metadata", {})
	not object.get(metadata, "enable-oslogin", null)
	instance_project := object.get(resource, "project", "")
	some _proj_key, pms in input.resource.google_compute_project_metadata
	some pm in pms
	object.get(pm, "project", "") == instance_project
	project_meta := object.get(pm, "metadata", {})
	lib.truthy(object.get(project_meta, "enable-oslogin", false))
}
