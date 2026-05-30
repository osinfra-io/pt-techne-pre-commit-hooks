package tofuscan

import rego.v1

_admin_roles := {"roles/admin", "roles/editor", "roles/owner"}

_desc_1_6 := concat("", [
	"Service accounts should use the minimum necessary permissions; ",
	"admin roles grant overly broad access to all GCP services.",
])

deny contains violation if {
	some name, resources in input.resource.google_project_iam_member
	some resource in resources
	startswith(resource.member, "serviceAccount:")
	resource.role in _admin_roles
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/1.6",
		"cis_control": "1.6",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That Service Account Has No Admin Privileges",
		"description": _desc_1_6,
	}
}
