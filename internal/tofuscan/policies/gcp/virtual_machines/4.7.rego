package tofuscan

import rego.v1

_desc_4_7 := concat("", [
	"Customer-Supplied Encryption Keys (CSEK) give organizations full control over the ",
	"encryption key lifecycle for VM disks. If Google is compelled to provide data, the ",
	"disks remain protected because Google does not hold the key material.",
])

deny contains violation if {
	some name, resources in input.resource.google_compute_disk
	some resource in resources
	not _has_csek(resource)
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/4.7",
		"cis_control": "4.7",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure VM Disks for Critical VMs Are Encrypted With Customer-Supplied Encryption Keys",
		"description": _desc_4_7,
	}
}

_has_csek(resource) if {
	some enc in object.get(resource, "disk_encryption_key", [])
	object.get(enc, "raw_key", "") != ""
}

_has_csek(resource) if {
	some enc in object.get(resource, "disk_encryption_key", [])
	object.get(enc, "rsa_encrypted_key", "") != ""
}
