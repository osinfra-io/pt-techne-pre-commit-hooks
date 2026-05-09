package regofu

import rego.v1

_desc_3_3 := concat("", [
	"DNSSEC prevents DNS spoofing and cache poisoning by cryptographically signing ",
	"DNS records, ensuring resolvers receive authentic responses.",
])

deny contains violation if {
	some name, resources in input.resource.google_dns_managed_zone
	some resource in resources
	dnssec_arr := object.get(resource, "dnssec_config", [{}])
	some dnssec in dnssec_arr
	object.get(dnssec, "state", "off") != "on"
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/3.3",
		"cis_control": "3.3",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure That DNSSEC Is Enabled for Cloud DNS",
		"description": _desc_3_3,
	}
}
