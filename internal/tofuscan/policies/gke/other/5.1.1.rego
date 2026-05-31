package tofuscan

import rego.v1

import data.tofuscan.lib

_valid_vuln_modes_5_1_1 := {"VULNERABILITY_BASIC", "VULNERABILITY_ENTERPRISE"}

_desc_5_1_1 := concat("", [
	"Container image vulnerability scanning detects known CVEs in workloads. Enabling ",
	"GKE Security Posture vulnerability scanning (security_posture_config.vulnerability_mode ",
	"set to VULNERABILITY_BASIC or VULNERABILITY_ENTERPRISE) surfaces vulnerable images.",
])

deny contains violation if {
	some name, resources in input.resource.google_container_cluster
	some resource in resources
	not _vuln_scanning_enabled(resource)
	violation := {
		"resource": concat(".", ["google_container_cluster", name]),
		"rule_id": "gke/cis/5.1.1",
		"cis_control": "5.1.1",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure Image Vulnerability Scanning is enabled",
		"description": _desc_5_1_1,
	}
}

_vuln_scanning_enabled(resource) if {
	some spc in object.get(resource, "security_posture_config", [])
	mode := object.get(spc, "vulnerability_mode", "")
	mode in _valid_vuln_modes_5_1_1
}

_vuln_scanning_enabled(resource) if {
	some spc in object.get(resource, "security_posture_config", [])
	lib.is_unresolved(object.get(spc, "vulnerability_mode", ""))
}
