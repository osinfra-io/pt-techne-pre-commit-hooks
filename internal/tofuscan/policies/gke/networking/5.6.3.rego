package tofuscan

import rego.v1

_desc_5_6_3 := concat("", [
	"Control Plane Authorized Networks restricts access to the GKE API server to ",
	"specific IP ranges, reducing the attack surface of the cluster control plane.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_cluster
	some resource in resources
	manc_arr := object.get(resource, "master_authorized_networks_config", [{}])
	some manc in manc_arr
	cidr_blocks := object.get(manc, "cidr_blocks", [])
	count(cidr_blocks) == 0
	violation := {
		"resource": name,
		"rule_id": "gke/cis/5.6.3",
		"cis_control": "5.6.3",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure Control Plane Authorized Networks Is Enabled",
		"description": _desc_5_6_3,
	}
}
