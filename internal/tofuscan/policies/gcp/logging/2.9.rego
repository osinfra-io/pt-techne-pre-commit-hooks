package tofuscan

import data.tofuscan.lib
import rego.v1

_violation_2_9 := {
	"resource": "global",
	"rule_id": "gcp/cis/2.9",
	"cis_control": "2.9",
	"profile_level": "Level 2",
	"severity": "Medium",
	"title": "Ensure That the Log Metric Filter and Alerts Exist for VPC Network Route Changes",
	"description": concat("", [
		"VPC route changes can redirect traffic to malicious destinations or expose internal ",
		"services. A metric filter and alert on gce_route changes enables detection of routing anomalies.",
	]),
}

# True when at least one metric matching the VPC route filter is wired to an alert.
_has_route_metric_with_alert if {
	some _label, resources in input.resource.google_logging_metric
	some resource in resources
	contains(object.get(resource, "filter", ""), "gce_route")
	metric_name := object.get(resource, "name", "")
	count(metric_name) > 0
	lib.alert_exists_for_metric(metric_name)
}

# No log metric filter exists for VPC network route changes.
deny contains _violation_2_9 if {
	input.resource.google_project
	not lib.metric_filter_exists("gce_route")
}

# Metric(s) matching the filter exist but none are wired to an alert.
deny contains _violation_2_9 if {
	input.resource.google_project
	lib.metric_filter_exists("gce_route")
	not _has_route_metric_with_alert
}
