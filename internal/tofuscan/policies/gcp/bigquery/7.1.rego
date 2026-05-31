package tofuscan

import rego.v1

import data.tofuscan.lib

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
		"resource": concat(".", ["google_bigquery_dataset", name]),
		"rule_id": "gcp/cis/7.1",
		"cis_control": "7.1",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That BigQuery Datasets Are Not Anonymously or Publicly Accessible",
		"description": _desc_7_1,
	}
}

# Inline access blocks can also grant public access via the iam_member field.
deny contains violation if {
	some name, resources in input.resource.google_bigquery_dataset
	some resource in resources
	some access in resource.access
	object.get(access, "iam_member", "") in _bq_public_groups
	violation := {
		"resource": concat(".", ["google_bigquery_dataset", name]),
		"rule_id": "gcp/cis/7.1",
		"cis_control": "7.1",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That BigQuery Datasets Are Not Anonymously or Publicly Accessible",
		"description": _desc_7_1,
	}
}

deny contains violation if {
	some name, resources in input.resource.google_bigquery_dataset_iam_member
	some resource in resources
	resource.member in _bq_public_groups
	violation := {
		"resource": concat(".", ["google_bigquery_dataset_iam_member", name]),
		"rule_id": "gcp/cis/7.1",
		"cis_control": "7.1",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That BigQuery Datasets Are Not Anonymously or Publicly Accessible",
		"description": _desc_7_1,
	}
}

deny contains violation if {
	some name, resources in input.resource.google_bigquery_dataset_iam_binding
	some resource in resources
	some member in resource.members
	member in _bq_public_groups
	violation := {
		"resource": concat(".", ["google_bigquery_dataset_iam_binding", name]),
		"rule_id": "gcp/cis/7.1",
		"cis_control": "7.1",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That BigQuery Datasets Are Not Anonymously or Publicly Accessible",
		"description": _desc_7_1,
	}
}

deny contains violation if {
	some name, resources in input.resource.google_bigquery_dataset_iam_policy
	some resource in resources
	lib.policy_data_public(object.get(resource, "policy_data", ""))
	violation := {
		"resource": concat(".", ["google_bigquery_dataset_iam_policy", name]),
		"rule_id": "gcp/cis/7.1",
		"cis_control": "7.1",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That BigQuery Datasets Are Not Anonymously or Publicly Accessible",
		"description": _desc_7_1,
	}
}
