package tofuscan

import rego.v1

_desc_8_1 := concat("", [
	"Encrypting Dataproc cluster data with a Customer-Managed Encryption Key (CMEK) ",
	"gives the organization control over the key lifecycle, enabling independent key ",
	"revocation and rotation without relying on Google-managed defaults.",
])

deny contains violation if {
	some name, resources in input.resource.google_dataproc_cluster
	some resource in resources
	cc_arr := object.get(resource, "cluster_config", [{}])
	some cc in cc_arr
	enc_arr := object.get(cc, "encryption_config", [{}])
	some enc in enc_arr
	object.get(enc, "kms_key_name", "") == ""
	violation := {
		"resource": concat(".", ["google_dataproc_cluster", name]),
		"rule_id": "gcp/cis/8.1",
		"cis_control": "8.1",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure That Dataproc Cluster Is Encrypted Using Customer-Managed Encryption Key",
		"description": _desc_8_1,
	}
}
