package regofu

import rego.v1

_desc_5_5_1 := concat("", [
	"Container-Optimized OS with containerd (cos_containerd) is a hardened OS ",
	"purpose-built for running containers on Google Cloud with a minimal attack surface.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_node_pool
	some resource in resources
	some nc in object.get(resource, "node_config", [{}])
	upper(object.get(nc, "image_type", "")) != "COS_CONTAINERD"
	violation := {
		"resource": name,
		"rule_id": "gke/cis/5.5.1",
		"cis_control": "5.5.1",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure Container-Optimized OS (cos_containerd) Is Used for GKE Node Images",
		"description": _desc_5_5_1,
	}
}
