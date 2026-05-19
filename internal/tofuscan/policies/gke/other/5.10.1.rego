package tofuscan

import rego.v1

_desc_5_10_1 := concat("", [
	"The Kubernetes web UI (Dashboard) is a potential attack surface that can expose ",
	"cluster resources. It should be disabled unless explicitly required.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_cluster
	some resource in resources
	some addons in object.get(resource, "addons_config", [{}])
	some dashboard in object.get(addons, "kubernetes_dashboard", [])
	object.get(dashboard, "disabled", true) != true
	violation := {
		"resource": name,
		"rule_id": "gke/cis/5.10.1",
		"cis_control": "5.10.1",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure Kubernetes Web UI Is Disabled",
		"description": _desc_5_10_1,
	}
}
