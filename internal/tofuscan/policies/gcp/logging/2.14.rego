package tofuscan

import rego.v1

_desc_2_14 := concat("", [
	"Cloud Asset Inventory provides a time-series record of GCP resource metadata and ",
	"IAM policies, enabling change tracking and compliance auditing. The ",
	"cloudasset.googleapis.com service must be enabled via a google_project_service resource.",
])

# Gated on google_project so the existence check only fires in a project-setup
# layer; if a project is configured but the Cloud Asset Inventory API is never
# enabled, asset change tracking is unavailable.
deny contains violation if {
	input.resource.google_project
	not _cloud_asset_enabled
	violation := {
		"resource": "global",
		"rule_id": "gcp/cis/2.14",
		"cis_control": "2.14",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure Cloud Asset Inventory Is Enabled",
		"description": _desc_2_14,
	}
}

_cloud_asset_enabled if {
	some _label, resources in input.resource.google_project_service
	some resource in resources
	object.get(resource, "service", "") == "cloudasset.googleapis.com"
}
