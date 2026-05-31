package tofuscan

import rego.v1

_desc_2_13 := concat("", [
	"Cloud DNS logs record DNS queries made from within VPC networks to Stackdriver, ",
	"providing visibility into potentially malicious DNS activity. ",
	"Note: this policy checks that any google_dns_policy resources present have logging enabled; ",
	"it does not verify that every VPC network has an associated DNS policy.",
])

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
