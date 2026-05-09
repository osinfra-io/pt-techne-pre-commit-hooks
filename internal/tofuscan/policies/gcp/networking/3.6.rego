package regofu

import rego.v1

import data.regofu.lib

_desc_3_6 := concat("", [
	"Firewall rules must not allow unrestricted inbound SSH (port 22) from ",
	"0.0.0.0/0 or ::/0. Expose SSH only through IAP or a bastion host.",
])

deny contains violation if {
	some name, resources in input.resource.google_compute_firewall
	some resource in resources
	some rule in resource.allow
	some port in rule.ports
	port == "22"
	some cidr in resource.source_ranges
	lib.is_public_cidr(cidr)
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/3.6",
		"cis_control": "3.6",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That SSH Access Is Restricted From the Internet",
		"description": _desc_3_6,
	}
}
