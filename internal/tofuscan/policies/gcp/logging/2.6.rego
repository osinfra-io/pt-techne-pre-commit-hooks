package tofuscan

import data.tofuscan.lib
import rego.v1

_violation_2_6 := {
	"resource": "global",
	"rule_id": "gcp/cis/2.6",
	"cis_control": "2.6",
	"profile_level": "Level 1",
	"severity": "Medium",
	"title": "Ensure That the Log Metric Filter and Alerts Exist for Audit Configuration Changes",
	"description": concat("", [
		"Changes to audit configuration could disable logging for critical events. Alerting on ",
		"auditConfigDeltas changes helps detect attempts to cover tracks by reducing audit coverage.",
	]),
}

# True when at least one metric matching the audit config filter is wired to an alert.
_has_audit_config_metric_with_alert if {
	some _label, resources in input.resource.google_logging_metric
	some resource in resources
	contains(object.get(resource, "filter", ""), "auditConfigDeltas")
	metric_name := object.get(resource, "name", "")
	count(metric_name) > 0
	lib.alert_exists_for_metric(metric_name)
}

# No log metric filter exists for audit configuration changes.
deny contains _violation_2_6 if {
	input.resource.google_project
	not lib.metric_filter_exists("auditConfigDeltas")
}

# Metric(s) matching the filter exist but none are wired to an alert.
deny contains _violation_2_6 if {
	input.resource.google_project
	lib.metric_filter_exists("auditConfigDeltas")
	not _has_audit_config_metric_with_alert
}
