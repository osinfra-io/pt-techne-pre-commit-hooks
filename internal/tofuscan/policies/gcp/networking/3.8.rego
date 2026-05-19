package tofuscan

import rego.v1

_desc_3_8 := concat("", [
	"VPC Flow Logs capture metadata about IP traffic on network interfaces, ",
	"enabling network forensics, anomaly detection, and security auditing.",
])

deny contains violation if {
	some name, resources in input.resource.google_compute_subnetwork
	some resource in resources
	not log_config_enabled(resource)
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/3.8",
		"cis_control": "3.8",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure that VPC Flow Logs is Enabled for Every Subnet in a VPC Network",
		"description": _desc_3_8,
	}
}

log_config_enabled(resource) if count(object.get(resource, "log_config", [])) > 0

# Dynamic blocks are emitted under the synthetic "dynamic" key by the parser.
log_config_enabled(resource) if {
	dynamic := object.get(resource, "dynamic", {})
	count(object.get(dynamic, "log_config", [])) > 0
}
