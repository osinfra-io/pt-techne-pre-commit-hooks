package tofuscan

import data.tofuscan.lib
import rego.v1

_desc_2_6 := concat("", [
	"Changes to audit configuration could disable logging for critical events. Alerting on ",
	"auditConfigDeltas changes helps detect attempts to cover tracks by reducing audit coverage.",
])

# No log metric filter exists for audit configuration changes.
deny contains violation if {
	input.resource.google_project
	not lib.metric_filter_exists("auditConfigDeltas")
	violation := {
		"resource": "global",
		"rule_id": "gcp/cis/2.6",
		"cis_control": "2.6",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure That the Log Metric Filter and Alerts Exist for Audit Configuration Changes",
		"description": _desc_2_6,
	}
}

# Log metric exists but no alert policy references it.
deny contains violation if {
	input.resource.google_project
	some _label, resources in input.resource.google_logging_metric
	some resource in resources
	contains(object.get(resource, "filter", ""), "auditConfigDeltas")
	metric_name := object.get(resource, "name", "")
	count(metric_name) > 0
	not lib.alert_exists_for_metric(metric_name)
	violation := {
		"resource": "global",
		"rule_id": "gcp/cis/2.6",
		"cis_control": "2.6",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure That the Log Metric Filter and Alerts Exist for Audit Configuration Changes",
		"description": _desc_2_6,
	}
}
