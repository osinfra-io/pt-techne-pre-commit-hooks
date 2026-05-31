package tofuscan

import rego.v1

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

# Instance-level metadata takes precedence; "true" or "TRUE" are both valid.
_oslogin_effective(resource) if {
	metadata := object.get(resource, "metadata", {})
	lower(object.get(metadata, "enable-oslogin", "")) == "true"
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
	lower(object.get(project_meta, "enable-oslogin", "")) == "true"
}
