package regofu

import rego.v1

_desc_3_1 := concat("", [
	"The default VPC network is automatically created in each project with permissive ",
	"firewall rules that allow ingress from any source. Projects should use custom VPC ",
	"networks with explicitly defined, least-privilege firewall rules instead.",
])

deny contains violation if {
	some name, resources in input.resource.google_compute_network
	some resource in resources
	resource.name == "default"
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/3.1",
		"cis_control": "3.1",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That the Default Network Does Not Exist in a Project",
		"description": _desc_3_1,
	}
}
