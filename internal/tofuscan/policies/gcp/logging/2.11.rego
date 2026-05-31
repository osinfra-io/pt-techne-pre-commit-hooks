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

# True when at least one metric matching the storage IAM filter is wired to an alert.
_has_storage_iam_metric_with_alert if {
	some _label, resources in input.resource.google_logging_metric
	some resource in resources
	contains(object.get(resource, "filter", ""), "storage.setIamPermissions")
	metric_name := object.get(resource, "name", "")
	count(metric_name) > 0
	lib.alert_exists_for_metric(metric_name)
}

# No log metric filter exists for Cloud Storage IAM permission changes.
deny contains _violation_2_11 if {
	input.resource.google_project
	not lib.metric_filter_exists("storage.setIamPermissions")
}

# Metric(s) matching the filter exist but none are wired to an alert.
deny contains _violation_2_11 if {
	input.resource.google_project
	lib.metric_filter_exists("storage.setIamPermissions")
	not _has_storage_iam_metric_with_alert
}
