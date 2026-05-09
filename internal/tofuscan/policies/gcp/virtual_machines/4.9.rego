package regofu

import rego.v1

_desc_4_9 := concat("", [
	"Instances with public IP addresses are directly reachable from the internet. ",
	"Use Cloud NAT or a bastion host for outbound access and IAP for inbound management.",
])

deny contains violation if {
	some name, resources in input.resource.google_compute_instance
	some resource in resources
	some iface in resource.network_interface
	access_configs := object.get(iface, "access_config", [])
	count(access_configs) > 0
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/4.9",
		"cis_control": "4.9",
		"profile_level": "Level 2",
		"severity": "High",
		"title": "Ensure That Compute Instances Do Not Have Public IP Addresses",
		"description": _desc_4_9,
	}
}
