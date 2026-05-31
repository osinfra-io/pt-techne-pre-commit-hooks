package tofuscan

import rego.v1

import data.tofuscan.lib

_desc_5_6_5 := concat("", [
	"Private nodes have no public IP addresses, preventing direct internet access to ",
	"cluster nodes and reducing the blast radius of a node compromise.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_cluster
	some resource in resources
	some pcc in object.get(resource, "private_cluster_config", [{}])
	value := object.get(pcc, "enable_private_nodes", false)
	not lib.is_unresolved(value)
	value != true
	violation := {
		"resource": concat(".", ["google_container_cluster", name]),
		"rule_id": "gke/cis/5.6.5",
		"cis_control": "5.6.5",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure Clusters Are Created with Private Nodes",
		"description": _desc_5_6_5,
	}
}
