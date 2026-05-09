package regofu

import rego.v1

_desc_4_6 := concat("", [
	"IP forwarding allows an instance to forward packets addressed to other hosts. ",
	"Unless the instance is functioning as a network appliance, this capability should be disabled.",
])

deny contains violation if {
	some name, resources in input.resource.google_compute_instance
	some resource in resources
	resource.can_ip_forward == true
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/4.6",
		"cis_control": "4.6",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure That IP Forwarding Is Not Enabled on Instances",
		"description": _desc_4_6,
	}
}
