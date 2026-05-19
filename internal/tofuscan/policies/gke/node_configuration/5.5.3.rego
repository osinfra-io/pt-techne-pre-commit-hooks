package tofuscan

import rego.v1

_desc_5_5_3 := concat("", [
	"Node auto-upgrade keeps node pools on the latest patched Kubernetes version, ",
	"reducing exposure to known vulnerabilities without manual maintenance.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_node_pool
	some resource in resources
	some mgmt in object.get(resource, "management", [{}])
	object.get(mgmt, "auto_upgrade", false) != true
	violation := {
		"resource": name,
		"rule_id": "gke/cis/5.5.3",
		"cis_control": "5.5.3",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure Node Auto-Upgrade Is Enabled for GKE Nodes",
		"description": _desc_5_5_3,
	}
}
