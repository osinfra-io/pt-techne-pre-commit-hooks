package tofuscan

import rego.v1

import data.tofuscan.lib

_public_members_1_10 := {"allUsers", "allAuthenticatedUsers"}

_desc_1_10 := concat("", [
	"Cloud KMS cryptokeys must not grant access to allUsers or allAuthenticatedUsers. ",
	"Publicly accessible encryption keys can be used to decrypt any data they protect, ",
	"completely undermining the purpose of encryption.",
])

deny contains violation if {
	some name, resources in input.resource.google_kms_crypto_key_iam_member
	some resource in resources
	resource.member in _public_members_1_10
	violation := {
		"resource": concat(".", ["google_kms_crypto_key_iam_member", name]),
		"rule_id": "gcp/cis/1.10",
		"cis_control": "1.10",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That Cloud KMS Cryptokeys Are Not Anonymously or Publicly Accessible",
		"description": _desc_1_10,
	}
}

deny contains violation if {
	some name, resources in input.resource.google_kms_crypto_key_iam_binding
	some resource in resources
	some member in resource.members
	member in _public_members_1_10
	violation := {
		"resource": concat(".", ["google_kms_crypto_key_iam_binding", name]),
		"rule_id": "gcp/cis/1.10",
		"cis_control": "1.10",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That Cloud KMS Cryptokeys Are Not Anonymously or Publicly Accessible",
		"description": _desc_1_10,
	}
}

deny contains violation if {
	some name, resources in input.resource.google_kms_crypto_key_iam_policy
	some resource in resources
	lib.policy_data_public(object.get(resource, "policy_data", ""))
	violation := {
		"resource": concat(".", ["google_kms_crypto_key_iam_policy", name]),
		"rule_id": "gcp/cis/1.10",
		"cis_control": "1.10",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That Cloud KMS Cryptokeys Are Not Anonymously or Publicly Accessible",
		"description": _desc_1_10,
	}
}
