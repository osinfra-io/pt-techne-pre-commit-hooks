package tofuscan

import rego.v1

_desc_5_9_1 := concat("", [
	"Encrypting the Kubernetes Secrets backend (etcd) with a Customer-Managed Encryption ",
	"Key (CMEK) gives the organization independent control over the key lifecycle, enabling ",
	"key revocation and rotation without relying on Google-managed defaults.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_cluster
	some resource in resources
	enc_arr := object.get(resource, "database_encryption", [{}])
	some enc in enc_arr
	object.get(enc, "key_name", "") == ""
	violation := {
		"resource": concat(".", ["google_container_cluster", name]),
		"rule_id": "gke/cis/5.9.1",
		"cis_control": "5.9.1",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Enable Customer-Managed Encryption Keys (CMEK) for GKE Persistent Disks",
		"description": _desc_5_9_1,
	}
}
