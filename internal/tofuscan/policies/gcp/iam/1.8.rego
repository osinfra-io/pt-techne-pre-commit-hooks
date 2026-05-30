package tofuscan

import rego.v1

_desc_1_8 := concat("", [
	"Service Account keys used to authenticate API requests must be rotated regularly ",
	"to limit exposure from key compromise.",
])

deny contains violation if {
	some name, resources in input.resource.google_iam_service_account_key
	some resource in resources
	key_type := object.get(resource, "key_type", "USER_MANAGED")
	key_type == "USER_MANAGED"
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/1.8",
		"cis_control": "1.8",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure User-Managed/External Keys for Service Accounts Are Rotated Every 90 Days or Fewer",
		"description": _desc_1_8,
	}
}
