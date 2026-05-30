package tofuscan

import rego.v1

_weak_tls_versions := {"TLS_1_0", "TLS_1_1"}

_desc_3_11 := concat("", [
	"SSL policies control the TLS version and cipher suites that HTTPS and SSL proxy ",
	"load balancers accept. Policies allowing TLS 1.0 or 1.1, or using the COMPATIBLE ",
	"profile, permit weak cipher suites that are vulnerable to downgrade attacks.",
])

deny contains violation if {
	some name, resources in input.resource.google_compute_ssl_policy
	some resource in resources
	min_tls := object.get(resource, "min_tls_version", "TLS_1_0")
	min_tls in _weak_tls_versions
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/3.11",
		"cis_control": "3.11",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure No HTTPS or SSL Proxy Load Balancers Permit SSL Policies With Weak Cipher Suites",
		"description": _desc_3_11,
	}
}

deny contains violation if {
	some name, resources in input.resource.google_compute_ssl_policy
	some resource in resources
	profile := object.get(resource, "profile", "COMPATIBLE")
	profile == "COMPATIBLE"
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/3.11",
		"cis_control": "3.11",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure No HTTPS or SSL Proxy Load Balancers Permit SSL Policies With Weak Cipher Suites",
		"description": _desc_3_11,
	}
}
