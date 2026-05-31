package tofuscan

import rego.v1

_desc_1_5 := concat("", [
	"User-managed service account keys are long-lived credentials that are difficult to ",
	"rotate, audit, and revoke. Only GCP-managed keys should be used; any creation of a ",
	"user-managed key via google_iam_service_account_key is a violation of this control.",
])

deny contains violation if {
	some name, resources in input.resource.google_iam_service_account_key
	some resource in resources
	object.get(resource, "key_type", "USER_MANAGED") != "GOOGLE_MANAGED"
	violation := {
		"resource": concat(".", ["google_iam_service_account_key", name]),
		"rule_id": "gcp/cis/1.5",
		"cis_control": "1.5",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That There Are Only GCP-Managed Service Account Keys for Each Service Account",
		"description": _desc_1_5,
	}
}
