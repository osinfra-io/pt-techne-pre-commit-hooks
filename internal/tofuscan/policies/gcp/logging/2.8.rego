package tofuscan

import data.tofuscan.lib
import rego.v1

_violation_2_8 := {
	"resource": "global",
	"rule_id": "gcp/cis/2.8",
	"cis_control": "2.8",
	"profile_level": "Level 2",
	"severity": "Medium",
	"title": "Ensure That the Log Metric Filter and Alerts Exist for VPC Network Firewall Rule Changes",
	"description": concat("", [
		"VPC firewall rule changes can open unintended network access paths. Metric filters and ",
		"alerts on gce_firewall_rule changes provide visibility into firewall configuration drift.",
	]),
}

# True when at least one metric matching the firewall rule filter is wired to an alert.
_has_firewall_metric_with_alert if {
	some _label, resources in input.resource.google_logging_metric
	some resource in resources
	contains(object.get(resource, "filter", ""), "gce_firewall_rule")
	metric_name := object.get(resource, "name", "")
	count(metric_name) > 0
	lib.alert_exists_for_metric(metric_name)
}

# No log metric filter exists for VPC firewall rule changes.
deny contains _violation_2_8 if {
	input.resource.google_project
	not lib.metric_filter_exists("gce_firewall_rule")
}

# Metric(s) matching the filter exist but none are wired to an alert.
deny contains _violation_2_8 if {
	input.resource.google_project
	lib.metric_filter_exists("gce_firewall_rule")
	not _has_firewall_metric_with_alert
}
