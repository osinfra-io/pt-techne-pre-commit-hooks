package tofuscan

import rego.v1

import data.tofuscan.lib

_desc_5_6_2 := concat("", [
	"VPC-native clusters use alias IP ranges, enabling direct pod-to-pod routing, ",
	"improved network performance, and better integration with GCP networking features.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_cluster
	some resource in resources
	not _is_vpc_native(resource)
	violation := {
		"resource": concat(".", ["google_container_cluster", name]),
		"rule_id": "gke/cis/5.6.2",
		"cis_control": "5.6.2",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure Use of VPC-Native Clusters",
		"description": _desc_5_6_2,
	}
}

_is_vpc_native(resource) if resource.networking_mode == "VPC_NATIVE"

_is_vpc_native(resource) if count(object.get(resource, "ip_allocation_policy", [])) > 0

# networking_mode supplied by a module output cannot be statically evaluated.
_is_vpc_native(resource) if lib.is_unresolved(object.get(resource, "networking_mode", ""))

# New clusters default to VPC-native unless networking_mode is set to ROUTES or a
# routes-based cluster_ipv4_cidr is supplied, so absence of both is compliant.
_is_vpc_native(resource) if {
	not resource.networking_mode
	object.get(resource, "cluster_ipv4_cidr", "") == ""
}
