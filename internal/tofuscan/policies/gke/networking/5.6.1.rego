package regofu

import rego.v1

_desc_5_6_1 := concat("", [
	"Enabling intranode visibility on a GKE cluster causes VPC Flow Logs to capture ",
	"pod-to-pod traffic within a single node. Without this setting, only inter-node ",
	"traffic is visible, leaving a blind spot for forensics and anomaly detection.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_cluster
	some resource in resources
	object.get(resource, "enable_intranode_visibility", false) != true
	violation := {
		"resource": name,
		"rule_id": "gke/cis/5.6.1",
		"cis_control": "5.6.1",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Enable VPC Flow Logs and Intranode Visibility",
		"description": _desc_5_6_1,
	}
}
