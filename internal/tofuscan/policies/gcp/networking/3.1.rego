package tofuscan

import rego.v1

import data.tofuscan.lib

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
		"resource": concat(".", ["google_compute_network", name]),
		"rule_id": "gcp/cis/3.1",
		"cis_control": "3.1",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That the Default Network Does Not Exist in a Project",
		"description": _desc_3_1,
	}
}

# auto_create_network defaults to true, which creates the permissive default
# network. A google_project must explicitly set auto_create_network = false.
deny contains violation if {
	some name, resources in input.resource.google_project
	some resource in resources
	value := object.get(resource, "auto_create_network", true)
	not lib.is_unresolved(value)
	value != false
	violation := {
		"resource": concat(".", ["google_project", name]),
		"rule_id": "gcp/cis/3.1",
		"cis_control": "3.1",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That the Default Network Does Not Exist in a Project",
		"description": _desc_3_1,
	}
}
