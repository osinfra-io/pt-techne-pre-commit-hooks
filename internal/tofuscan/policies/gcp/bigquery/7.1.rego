package regofu

import rego.v1

_bq_public_groups := {"allUsers", "allAuthenticatedUsers"}

_desc_7_1 := concat("", [
	"BigQuery dataset IAM policies must not include allUsers or ",
	"allAuthenticatedUsers, which would expose potentially sensitive analytical data to the public.",
])

deny contains violation if {
	some name, resources in input.resource.google_bigquery_dataset
	some resource in resources
	some access in resource.access
	access.special_group in _bq_public_groups
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/7.1",
		"cis_control": "7.1",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That BigQuery Datasets Are Not Anonymously or Publicly Accessible",
		"description": _desc_7_1,
	}
}
