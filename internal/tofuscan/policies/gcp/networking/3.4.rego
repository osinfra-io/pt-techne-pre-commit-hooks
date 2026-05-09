package regofu

import rego.v1

_desc_3_4 := concat("", [
	"RSASHA1 is a weak algorithm for DNSSEC key signing. SHA-1 has known weaknesses; ",
	"use RSASHA256 or ECDSAP256SHA256 instead.",
])

deny contains violation if {
	some name, resources in input.resource.google_dns_managed_zone
	some resource in resources
	dnssec_arr := object.get(resource, "dnssec_config", [{}])
	some dnssec in dnssec_arr
	key_specs := object.get(dnssec, "default_key_specs", [])
	some spec in key_specs
	spec.algorithm == "rsasha1"
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/3.4",
		"cis_control": "3.4",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure That RSASHA1 Is Not Used for the Key-Signing Key in Cloud DNS DNSSEC",
		"description": _desc_3_4,
	}
}
