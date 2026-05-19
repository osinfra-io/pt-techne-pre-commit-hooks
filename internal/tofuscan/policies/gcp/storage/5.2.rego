package tofuscan

import rego.v1

_desc_5_2 := concat("", [
	"Uniform bucket-level access disables per-object ACLs and enforces IAM-only ",
	"access control, preventing inconsistent permissions that could inadvertently expose objects.",
])

deny contains violation if {
	some name, resources in input.resource.google_storage_bucket
	some resource in resources
	object.get(resource, "uniform_bucket_level_access", false) != true
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/5.2",
		"cis_control": "5.2",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure That Cloud Storage Buckets Have Uniform Bucket-Level Access Enabled",
		"description": _desc_5_2,
	}
}
