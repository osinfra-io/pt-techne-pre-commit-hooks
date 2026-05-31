package tofuscan

import data.tofuscan.lib
import rego.v1

_violation_2_12 := {
	"resource": "global",
	"rule_id": "gcp/cis/2.12",
	"cis_control": "2.12",
	"profile_level": "Level 2",
	"severity": "Medium",
	"title": "Ensure That the Log Metric Filter and Alerts Exist for SQL Instance Configuration Changes",
	"description": concat("", [
		"SQL instance configuration changes — such as disabling SSL or enabling public IP — can ",
		"weaken database security. Alerting on cloudsql.instances.update events ensures these ",
		"changes are detected and reviewed promptly.",
	]),
}

# True when at least one metric matching the SQL instance filter is wired to an alert.
_has_sql_metric_with_alert if {
	some _label, resources in input.resource.google_logging_metric
	some resource in resources
	contains(object.get(resource, "filter", ""), "cloudsql.instances.update")
	metric_name := object.get(resource, "name", "")
	count(metric_name) > 0
	lib.alert_exists_for_metric(metric_name)
}

# No log metric filter exists for SQL instance configuration changes.
deny contains _violation_2_12 if {
	input.resource.google_project
	not lib.metric_filter_exists("cloudsql.instances.update")
}

# Metric(s) matching the filter exist but none are wired to an alert.
deny contains _violation_2_12 if {
	input.resource.google_project
	lib.metric_filter_exists("cloudsql.instances.update")
	not _has_sql_metric_with_alert
}
