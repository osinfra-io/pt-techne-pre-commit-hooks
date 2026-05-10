package regofu

import rego.v1

_desc_3_3 := concat("", [
	"DNSSEC prevents DNS spoofing and cache poisoning by cryptographically signing ",
	"DNS records, ensuring resolvers receive authentic responses.",
])

deny contains violation if {
	some name, resources in input.resource.google_dns_managed_zone
	some resource in resources
	not dnssec_enabled(resource)
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

dnssec_enabled(resource) if {
	dnssec_arr := object.get(resource, "dnssec_config", [])
	some dnssec in dnssec_arr
	lower(object.get(dnssec, "state", "off")) == "on"
}

# Dynamic blocks are emitted under the synthetic "dynamic" key by the parser.
# If dnssec_config is present there, treat this as configured and avoid false positives.
dnssec_enabled(resource) if {
	dynamic := object.get(resource, "dynamic", {})
	count(object.get(dynamic, "dnssec_config", [])) > 0
}
