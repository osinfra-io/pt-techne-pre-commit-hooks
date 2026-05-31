package tofuscan

import data.tofuscan.lib
import rego.v1

_violation_2_10 := {
	"resource": "global",
	"rule_id": "gcp/cis/2.10",
	"cis_control": "2.10",
	"profile_level": "Level 2",
	"severity": "Medium",
	"title": "Ensure That the Log Metric Filter and Alerts Exist for VPC Network Changes",
	"description": concat("", [
		"Changes to VPC networks — such as peering, subnet modifications, or deletion — can alter ",
		"the network security boundary. Alerting on gce_network changes enables early detection ",
		"of unauthorized network modifications.",
	]),
}

# True when at least one metric matching the VPC network filter is wired to an alert.
_has_network_metric_with_alert if {
	some _label, resources in input.resource.google_logging_metric
	some resource in resources
	contains(object.get(resource, "filter", ""), "gce_network")
	metric_name := object.get(resource, "name", "")
	count(metric_name) > 0
	lib.alert_exists_for_metric(metric_name)
}

# No log metric filter exists for VPC network changes.
deny contains _violation_2_10 if {
	input.resource.google_project
	not lib.metric_filter_exists("gce_network")
}

# Metric(s) matching the filter exist but none are wired to an alert.
deny contains _violation_2_10 if {
	input.resource.google_project
	lib.metric_filter_exists("gce_network")
	not _has_network_metric_with_alert
}
