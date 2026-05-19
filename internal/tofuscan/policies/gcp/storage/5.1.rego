package tofuscan

import rego.v1

_public_members := {"allUsers", "allAuthenticatedUsers"}

_desc_5_1 := concat("", [
	"IAM policies on Cloud Storage buckets must not grant access to allUsers or ",
	"allAuthenticatedUsers, which would expose bucket contents to the public internet.",
])

deny contains violation if {
	some name, resources in input.resource.google_storage_bucket_iam_member
	some resource in resources
	resource.member in _public_members
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/5.1",
		"cis_control": "5.1",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That Cloud Storage Bucket Is Not Anonymously or Publicly Accessible",
		"description": _desc_5_1,
	}
}

deny contains violation if {
	some name, resources in input.resource.google_storage_bucket_iam_binding
	some resource in resources
	some member in resource.members
	member in _public_members
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/5.1",
		"cis_control": "5.1",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That Cloud Storage Bucket Is Not Anonymously or Publicly Accessible",
		"description": _desc_5_1,
	}
}
