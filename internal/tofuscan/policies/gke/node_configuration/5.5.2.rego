package tofuscan

import rego.v1

_desc_5_5_2 := concat("", [
	"Node auto-repair monitors node health and automatically repairs nodes that fail ",
	"health checks, reducing cluster downtime and manual intervention.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_node_pool
	some resource in resources
	some mgmt in object.get(resource, "management", [{}])
	object.get(mgmt, "auto_repair", false) != true
	violation := {
		"resource": concat(".", ["google_container_node_pool", name]),
		"rule_id": "gke/cis/5.5.2",
		"cis_control": "5.5.2",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure Node Auto-Repair Is Enabled for GKE Nodes",
		"description": _desc_5_5_2,
	}
}
