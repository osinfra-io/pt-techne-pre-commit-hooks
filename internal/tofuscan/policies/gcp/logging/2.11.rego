package tofuscan

import data.tofuscan.lib
import rego.v1

_violation_2_11 := {
	"resource": "global",
	"rule_id": "gcp/cis/2.11",
	"cis_control": "2.11",
	"profile_level": "Level 2",
	"severity": "Medium",
	"title": "Ensure That the Log Metric Filter and Alerts Exist for Cloud Storage IAM Permission Changes",
	"description": concat("", [
		"IAM permission changes on Cloud Storage buckets can expose sensitive data to unauthorized ",
		"principals. Monitoring storage.setIamPermissions events enables early detection of ",
		"unauthorized access grants.",
	]),
}

# No log metric filter exists for Cloud Storage IAM permission changes.
deny contains _violation_2_11 if {
	input.resource.google_project
	not lib.metric_filter_exists("storage.setIamPermissions")
}

# Log metric exists but no alert policy references it.
deny contains _violation_2_11 if {
	input.resource.google_project
	some _label, resources in input.resource.google_logging_metric
	some resource in resources
	contains(object.get(resource, "filter", ""), "storage.setIamPermissions")
	metric_name := object.get(resource, "name", "")
	count(metric_name) > 0
	not lib.alert_exists_for_metric(metric_name)
}
