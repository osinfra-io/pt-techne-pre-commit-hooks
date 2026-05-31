package tofuscan

import rego.v1

_desc_2_13 := concat("", [
	"Cloud DNS logs record DNS queries made from within VPC networks to Stackdriver, ",
	"providing visibility into potentially malicious DNS activity. ",
	"DNS logging must be explicitly enabled via a google_dns_policy resource; if none exists, ",
	"logging is disabled for all VPC networks.",
])

# No google_dns_policy resource is defined — DNS logging is disabled by default.
deny contains violation if {
	not input.resource.google_dns_policy
	violation := {
		"resource": "global",
		"rule_id": "gcp/cis/2.13",
		"cis_control": "2.13",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That Cloud DNS Logging Is Enabled for All VPC Networks",
		"description": _desc_2_13,
	}
}

# google_dns_policy resource exists but logging is not enabled.
deny contains violation if {
	some name, resources in input.resource.google_dns_policy
	some resource in resources
	not resource.enable_logging == true
	violation := {
		"resource": concat(".", ["google_dns_policy", name]),
		"rule_id": "gcp/cis/2.13",
		"cis_control": "2.13",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That Cloud DNS Logging Is Enabled for All VPC Networks",
		"description": _desc_2_13,
	}
}
