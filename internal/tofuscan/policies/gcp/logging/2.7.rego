package tofuscan

import data.tofuscan.lib
import rego.v1

_desc_2_7 := concat("", [
	"Custom IAM roles can be modified to include broader permissions than intended. Monitoring ",
	"changes to iam_role resources detects unauthorized privilege expansion in real time.",
])

# No log metric filter exists for custom role changes.
deny contains violation if {
	input.resource.google_project
	not lib.metric_filter_exists("iam_role")
	violation := {
		"resource": "global",
		"rule_id": "gcp/cis/2.7",
		"cis_control": "2.7",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure That the Log Metric Filter and Alerts Exist for Custom Role Changes",
		"description": _desc_2_7,
	}
}

# Log metric exists but no alert policy references it.
deny contains violation if {
	input.resource.google_project
	some _label, resources in input.resource.google_logging_metric
	some resource in resources
	contains(object.get(resource, "filter", ""), "iam_role")
	metric_name := object.get(resource, "name", "")
	count(metric_name) > 0
	not lib.alert_exists_for_metric(metric_name)
	violation := {
		"resource": "global",
		"rule_id": "gcp/cis/2.7",
		"cis_control": "2.7",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure That the Log Metric Filter and Alerts Exist for Custom Role Changes",
		"description": _desc_2_7,
	}
}
