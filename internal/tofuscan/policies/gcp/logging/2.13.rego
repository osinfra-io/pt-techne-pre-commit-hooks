package tofuscan

import rego.v1

_desc_2_13 := concat("", [
	"Cloud DNS logs record DNS queries made from within VPC networks to Stackdriver, ",
	"providing visibility into potentially malicious DNS activity. ",
	"DNS logging must be explicitly enabled via a google_dns_policy resource; if none exists, ",
	"logging is disabled for all VPC networks.",
])

# No google_dns_policy resource is defined — DNS logging is disabled by default.
# Gated on google_project so the check only fires in a project-setup layer and does
# not bleed into unrelated module scans that legitimately contain no DNS policy.
deny contains violation if {
	input.resource.google_project
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
