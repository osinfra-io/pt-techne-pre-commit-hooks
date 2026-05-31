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

# No log metric filter exists for SQL instance configuration changes.
deny contains _violation_2_12 if {
	input.resource.google_project
	not lib.metric_filter_exists("cloudsql.instances.update")
}

# Log metric exists but no alert policy references it.
deny contains _violation_2_12 if {
	input.resource.google_project
	some _label, resources in input.resource.google_logging_metric
	some resource in resources
	contains(object.get(resource, "filter", ""), "cloudsql.instances.update")
	metric_name := object.get(resource, "name", "")
	count(metric_name) > 0
	not lib.alert_exists_for_metric(metric_name)
}
