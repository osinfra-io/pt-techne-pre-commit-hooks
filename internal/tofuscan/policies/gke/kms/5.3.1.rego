package tofuscan

import rego.v1

_desc_5_3_1 := concat("", [
	"Application-layer encryption of Kubernetes Secrets using a Cloud KMS key adds a ",
	"second layer of defense against unauthorized access to secret data stored in etcd.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_cluster
	some resource in resources
	enc_arr := object.get(resource, "database_encryption", [{}])
	some enc in enc_arr
	object.get(enc, "state", "DECRYPTED") != "ENCRYPTED"
	violation := {
		"resource": name,
		"rule_id": "gke/cis/5.3.1",
		"cis_control": "5.3.1",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure Kubernetes Secrets Are Encrypted Using Keys Managed in Cloud KMS",
		"description": _desc_5_3_1,
	}
}
