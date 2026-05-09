package regofu

import rego.v1

_desc_5_4_1 := concat("", [
	"The GKE Metadata Server prevents pods from accessing sensitive VM metadata ",
	"via the legacy metadata endpoint and is required for Workload Identity.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_node_pool
	some resource in resources
	some nc in object.get(resource, "node_config", [{}])
	some wmc in object.get(nc, "workload_metadata_config", [{}])
	object.get(wmc, "mode", "") != "GKE_METADATA"
	violation := {
		"resource": name,
		"rule_id": "gke/cis/5.4.1",
		"cis_control": "5.4.1",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure the GKE Metadata Server Is Enabled",
		"description": _desc_5_4_1,
	}
}
