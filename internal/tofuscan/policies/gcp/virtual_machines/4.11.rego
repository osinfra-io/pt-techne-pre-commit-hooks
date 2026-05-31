package tofuscan

import rego.v1

import data.tofuscan.lib

_desc_4_11 := concat("", [
	"Confidential Computing encrypts data in-use while it is being processed in ",
	"memory using AMD SEV, preventing the hypervisor or Google from reading VM memory.",
])

deny contains violation if {
	some name, resources in input.resource.google_compute_instance
	some resource in resources
	not resource.confidential_instance_config
	violation := {
		"resource": concat(".", ["google_compute_instance", name]),
		"rule_id": "gcp/cis/4.11",
		"cis_control": "4.11",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure That Compute Instances Have Confidential Computing Enabled",
		"description": _desc_4_11,
	}
}

deny contains violation if {
	some name, resources in input.resource.google_compute_instance
	some resource in resources
	some config in resource.confidential_instance_config
	value := object.get(config, "enable_confidential_compute", false)
	not lib.is_unresolved(value)
	value != true
	violation := {
		"resource": concat(".", ["google_compute_instance", name]),
		"rule_id": "gcp/cis/4.11",
		"cis_control": "4.11",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure That Compute Instances Have Confidential Computing Enabled",
		"description": _desc_4_11,
	}
}
