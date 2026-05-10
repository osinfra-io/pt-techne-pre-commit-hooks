package regofu

import rego.v1

_desc_5_2_1 := concat("", [
	"The Compute Engine default service account has broad project-level permissions. ",
	"GKE node pools should use a dedicated, least-privilege service account instead.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_node_pool
	some resource in resources
	some nc in object.get(resource, "node_config", [{}])
	sa := lower(object.get(nc, "service_account", "default"))
	_is_default_gke_sa(sa)
	violation := {
		"resource": name,
		"rule_id": "gke/cis/5.2.1",
		"cis_control": "5.2.1",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure GKE Clusters Are Not Running Using the Compute Engine Default Service Account",
		"description": _desc_5_2_1,
	}
}

_is_default_gke_sa("default")

_is_default_gke_sa(sa) if endswith(sa, "-compute@developer.gserviceaccount.com")
