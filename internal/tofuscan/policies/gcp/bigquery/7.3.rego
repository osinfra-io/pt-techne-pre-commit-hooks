package tofuscan

import rego.v1

_desc_7_3 := concat("", [
	"Setting a default CMEK on a BigQuery dataset ensures that all newly created tables ",
	"in that dataset are automatically encrypted with the organization's own keys, ",
	"without requiring per-table encryption configuration.",
])

deny contains violation if {
	some name, resources in input.resource.google_bigquery_dataset
	some resource in resources
	not _has_default_cmek(resource)
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/7.3",
		"cis_control": "7.3",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure That a Default Customer-Managed Encryption Key Is Specified for All BigQuery Data Sets",
		"description": _desc_7_3,
	}
}

_has_default_cmek(resource) if {
	some enc in object.get(resource, "default_encryption_configuration", [])
	object.get(enc, "kms_key_name", "") != ""
}
