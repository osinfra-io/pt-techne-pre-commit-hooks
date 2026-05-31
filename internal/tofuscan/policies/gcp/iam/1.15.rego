package tofuscan

import rego.v1

import data.tofuscan.lib

_desc_1_15 := concat("", [
	"API keys should be restricted to only the APIs an application actually needs. ",
	"An unrestricted key (no api_targets) can be used to access any enabled GCP service ",
	"if it is exposed, dramatically increasing the blast radius of a leak.",
])

deny contains violation if {
	some name, resources in input.resource.google_apikeys_key
	some resource in resources
	not _has_api_targets(resource)
	violation := {
		"resource": concat(".", ["google_apikeys_key", name]),
		"rule_id": "gcp/cis/1.15",
		"cis_control": "1.15",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure API Keys Are Restricted to Only APIs That Application Needs Access",
		"description": _desc_1_15,
	}
}

_has_api_targets(resource) if {
	some restrictions in object.get(resource, "restrictions", [])
	count(object.get(restrictions, "api_targets", [])) > 0
}
