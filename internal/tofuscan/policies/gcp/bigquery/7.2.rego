package regofu

import rego.v1

_desc_7_2 := concat("", [
	"By default, BigQuery uses Google-managed encryption keys. Using Customer-Managed ",
	"Encryption Keys (CMEK) gives organizations control over key rotation and revocation, ",
	"ensuring that data becomes inaccessible if the key is deleted or disabled.",
])

deny contains violation if {
	some name, resources in input.resource.google_bigquery_table
	some resource in resources
	not _has_cmek(resource)
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/7.2",
		"cis_control": "7.2",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure That All BigQuery Tables Are Encrypted With Customer-Managed Encryption Key",
		"description": _desc_7_2,
	}
}

_has_cmek(resource) if {
	some enc in object.get(resource, "encryption_configuration", [])
	object.get(enc, "kms_key_name", "") != ""
}
