package tofuscan

import rego.v1

_desc_5_8_1 := concat("", [
	"Client certificate authentication is deprecated and weaker than modern ",
	"authentication methods. Disabling it enforces use of stronger auth mechanisms.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_cluster
	some resource in resources
	some ma in object.get(resource, "master_auth", [{}])
	some ccc in object.get(ma, "client_certificate_config", [{}])
	ccc.issue_client_certificate == true
	violation := {
		"resource": name,
		"rule_id": "gke/cis/5.8.1",
		"cis_control": "5.8.1",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure Authentication Using Client Certificates Is Disabled",
		"description": _desc_5_8_1,
	}
}
