package regofu

import rego.v1

_desc_4_1 := concat("", [
	"The default Compute Engine service account has the Editor role on the project. ",
	"Instances should use a dedicated, least-privilege service account instead.",
])

deny contains violation if {
	some name, resources in input.resource.google_compute_instance
	some resource in resources
	some sa in resource.service_account
	endswith(sa.email, "-compute@developer.gserviceaccount.com")
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/4.1",
		"cis_control": "4.1",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure That Instances Are Not Configured To Use the Default Service Account",
		"description": _desc_4_1,
	}
}
