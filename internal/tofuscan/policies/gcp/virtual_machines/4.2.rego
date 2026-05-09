package regofu

import rego.v1

_title_4_2 := concat("", [
	"Ensure That Instances Are Not Configured To Use the Default ",
	"Service Account With Full Access to All Cloud APIs",
])

_desc_4_2 := concat("", [
	"Even if the default service account is used, granting full access to all ",
	"Cloud APIs is excessively permissive and should be avoided.",
])

deny contains violation if {
	some name, resources in input.resource.google_compute_instance
	some resource in resources
	some sa in resource.service_account
	endswith(sa.email, "-compute@developer.gserviceaccount.com")
	some scope in sa.scopes
	contains(scope, "cloud-platform")
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/4.2",
		"cis_control": "4.2",
		"profile_level": "Level 1",
		"severity": "High",
		"title": _title_4_2,
		"description": _desc_4_2,
	}
}
