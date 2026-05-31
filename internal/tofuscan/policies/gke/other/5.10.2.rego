package tofuscan

import rego.v1

_desc_5_10_2 := concat("", [
	"Alpha clusters expose unstable Kubernetes features and are not covered by the ",
	"GKE SLA. They should never be used for production workloads.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_cluster
	some resource in resources
	resource.enable_kubernetes_alpha == true
	violation := {
		"resource": concat(".", ["google_container_cluster", name]),
		"rule_id": "gke/cis/5.10.2",
		"cis_control": "5.10.2",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure Alpha Clusters Are Not Used for Production Workloads",
		"description": _desc_5_10_2,
	}
}
