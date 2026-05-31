package tofuscan

import rego.v1

_desc_5_9_2 := concat("", [
	"Encrypting GKE node boot disks with a Customer-Managed Encryption Key (CMEK) ensures ",
	"that node OS data is encrypted with customer-controlled keys, providing independent ",
	"key revocation beyond Google-managed default encryption.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_node_pool
	some resource in resources
	some nc in object.get(resource, "node_config", [{}])
	object.get(nc, "boot_disk_kms_key", "") == ""
	violation := {
		"resource": concat(".", ["google_container_node_pool", name]),
		"rule_id": "gke/cis/5.9.2",
		"cis_control": "5.9.2",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Enable Customer-Managed Encryption Keys (CMEK) for Boot Disks",
		"description": _desc_5_9_2,
	}
}

deny contains violation if {
	some name, resources in input.resource.google_container_cluster
	some resource in resources
	some nc in object.get(resource, "node_config", [])
	object.get(nc, "boot_disk_kms_key", "") == ""
	violation := {
		"resource": concat(".", ["google_container_cluster", name]),
		"rule_id": "gke/cis/5.9.2",
		"cis_control": "5.9.2",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Enable Customer-Managed Encryption Keys (CMEK) for Boot Disks",
		"description": _desc_5_9_2,
	}
}
