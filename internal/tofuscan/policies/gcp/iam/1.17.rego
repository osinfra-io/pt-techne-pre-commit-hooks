package tofuscan

import rego.v1

_desc_1_17 := concat("", [
	"Essential Contacts ensures Google can deliver important security, technical, and ",
	"operational notifications to designated recipients. At least one ",
	"google_essential_contacts_contact must be defined for the project.",
])

# Gated on google_project so the existence check only fires in a project-setup
# layer; if a project is configured but no Essential Contact is declared, GCP has
# no recipient for critical notifications.
deny contains violation if {
	input.resource.google_project
	not input.resource.google_essential_contacts_contact
	violation := {
		"resource": "global",
		"rule_id": "gcp/cis/1.17",
		"cis_control": "1.17",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure Essential Contacts is Configured for Organization",
		"description": _desc_1_17,
	}
}
