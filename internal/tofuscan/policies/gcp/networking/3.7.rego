package tofuscan

import rego.v1

import data.tofuscan.lib

_desc_3_7 := concat("", [
	"Firewall rules must not allow unrestricted inbound RDP (port 3389) from ",
	"0.0.0.0/0 or ::/0. Expose RDP only through IAP or a bastion host.",
])

deny contains violation if {
	some name, resources in input.resource.google_compute_firewall
	some resource in resources
	some rule in resource.allow
	lower(object.get(rule, "protocol", "")) == "tcp"
	lib.port_covered(object.get(rule, "ports", []), 3389)
	some cidr in resource.source_ranges
	lib.is_public_cidr(cidr)
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/3.7",
		"cis_control": "3.7",
		"profile_level": "Level 2",
		"severity": "High",
		"title": "Ensure That RDP Access Is Restricted From the Internet",
		"description": _desc_3_7,
	}
}

deny contains violation if {
	some name, resources in input.resource.google_compute_firewall
	some resource in resources
	some rule in resource.allow
	lower(object.get(rule, "protocol", "")) == "tcp"
	not rule.ports
	some cidr in resource.source_ranges
	lib.is_public_cidr(cidr)
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/3.7",
		"cis_control": "3.7",
		"profile_level": "Level 2",
		"severity": "High",
		"title": "Ensure That RDP Access Is Restricted From the Internet",
		"description": _desc_3_7,
	}
}

deny contains violation if {
	some name, resources in input.resource.google_compute_firewall
	some resource in resources
	some rule in resource.allow
	lower(object.get(rule, "protocol", "")) == "all"
	some cidr in resource.source_ranges
	lib.is_public_cidr(cidr)
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/3.7",
		"cis_control": "3.7",
		"profile_level": "Level 2",
		"severity": "High",
		"title": "Ensure That RDP Access Is Restricted From the Internet",
		"description": _desc_3_7,
	}
}
