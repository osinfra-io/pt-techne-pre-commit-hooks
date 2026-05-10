package regofu

import rego.v1

# 7776000 seconds = 90 days
_max_rotation_seconds := 7776000

_desc_1_10 := concat("", [
	"KMS keys should be rotated at least every 90 days. Rotation limits the data ",
	"exposed if a key is compromised and is controlled via a rotation schedule on each CryptoKey.",
])

deny contains violation if {
	some name, resources in input.resource.google_kms_crypto_key
	some resource in resources
	not resource.rotation_period
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/1.10",
		"cis_control": "1.10",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure KMS Encryption Keys Are Rotated Within a Period of 90 Days",
		"description": _desc_1_10,
	}
}

deny contains violation if {
	some name, resources in input.resource.google_kms_crypto_key
	some resource in resources
	period := object.get(resource, "rotation_period", "")

	# Parse strict seconds format like "7776000s"
	regex.match(`^[0-9]+s$`, period)
	seconds_str := trim_suffix(period, "s")
	seconds := to_number(seconds_str)
	seconds > _max_rotation_seconds
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/1.10",
		"cis_control": "1.10",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure KMS Encryption Keys Are Rotated Within a Period of 90 Days",
		"description": _desc_1_10,
	}
}

deny contains violation if {
	some name, resources in input.resource.google_kms_crypto_key
	some resource in resources
	period := object.get(resource, "rotation_period", "")
	period != ""
	not regex.match(`^[0-9]+s$`, period)
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/1.10",
		"cis_control": "1.10",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure KMS Encryption Keys Are Rotated Within a Period of 90 Days",
		"description": _desc_1_10,
	}
}
