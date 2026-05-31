package tofuscan

import data.tofuscan.lib
import rego.v1

_violation_2_7 := {
	"resource": "global",
	"rule_id": "gcp/cis/2.7",
	"cis_control": "2.7",
	"profile_level": "Level 1",
	"severity": "Medium",
	"title": "Ensure That the Log Metric Filter and Alerts Exist for Custom Role Changes",
	"description": concat("", [
		"Custom IAM roles can be modified to include broader permissions than intended. Monitoring ",
		"changes to iam_role resources detects unauthorized privilege expansion in real time.",
	]),
}

# True when at least one metric matching the custom role filter is wired to an alert.
_has_custom_role_metric_with_alert if {
	some _label, resources in input.resource.google_logging_metric
	some resource in resources
	contains(object.get(resource, "filter", ""), "iam_role")
	metric_name := object.get(resource, "name", "")
	count(metric_name) > 0
	lib.alert_exists_for_metric(metric_name)
}

# No log metric filter exists for custom role changes.
deny contains _violation_2_7 if {
	input.resource.google_project
	not lib.metric_filter_exists("iam_role")
}

# Metric(s) matching the filter exist but none are wired to an alert.
deny contains _violation_2_7 if {
	input.resource.google_project
	lib.metric_filter_exists("iam_role")
	not _has_custom_role_metric_with_alert
}
