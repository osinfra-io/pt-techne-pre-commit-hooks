package tofuscan

import rego.v1

_desc_5_10_3 := concat("", [
	"GKE Sandbox uses gVisor to provide an additional layer of isolation between the host ",
	"kernel and containerized workloads. Node pools running untrusted or multi-tenant code ",
	"should enable gVisor to reduce the impact of container escape vulnerabilities.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_node_pool
	some resource in resources
	some nc in object.get(resource, "node_config", [{}])
	some sc in object.get(nc, "sandbox_config", [{}])
	upper(object.get(sc, "sandbox_type", "")) != "GVISOR"
	violation := {
		"resource": concat(".", ["google_container_node_pool", name]),
		"rule_id": "gke/cis/5.10.3",
		"cis_control": "5.10.3",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Consider GKE Sandbox for Running Untrusted Workloads",
		"description": _desc_5_10_3,
	}
}
