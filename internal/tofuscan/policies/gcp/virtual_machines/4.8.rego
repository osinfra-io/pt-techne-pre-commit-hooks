package regofu

import rego.v1

_desc_4_8 := concat("", [
	"Shielded VMs use Secure Boot, vTPM-enabled measured boot, and integrity ",
	"monitoring to defend against boot-level and firmware-level attacks.",
])

deny contains violation if {
	some name, resources in input.resource.google_compute_instance
	some resource in resources
	config_arr := object.get(resource, "shielded_instance_config", [{}])
	some cfg in config_arr
	not _shielded_vm_ok(cfg)
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/4.8",
		"cis_control": "4.8",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure Compute Instances Are Launched With Shielded VM Enabled",
		"description": _desc_4_8,
	}
}

_shielded_vm_ok(cfg) if {
	object.get(cfg, "enable_vtpm", false) == true
	object.get(cfg, "enable_integrity_monitoring", false) == true
}
