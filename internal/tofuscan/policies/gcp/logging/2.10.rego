package tofuscan

import data.tofuscan.lib
import rego.v1

_desc_2_10 := concat("", [
	"Changes to VPC networks — such as peering, subnet modifications, or deletion — can alter ",
	"the network security boundary. Alerting on gce_network changes enables early detection ",
	"of unauthorized network modifications.",
])

# No log metric filter exists for VPC network changes.
deny contains violation if {
	input.resource.google_project
	not lib.metric_filter_exists("gce_network")
	violation := {
		"resource": "global",
		"rule_id": "gcp/cis/2.10",
		"cis_control": "2.10",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure That the Log Metric Filter and Alerts Exist for VPC Network Changes",
		"description": _desc_2_10,
	}
}

# Log metric exists but no alert policy references it.
deny contains violation if {
	input.resource.google_project
	some _label, resources in input.resource.google_logging_metric
	some resource in resources
	contains(object.get(resource, "filter", ""), "gce_network")
	metric_name := object.get(resource, "name", "")
	count(metric_name) > 0
	not lib.alert_exists_for_metric(metric_name)
	violation := {
		"resource": "global",
		"rule_id": "gcp/cis/2.10",
		"cis_control": "2.10",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure That the Log Metric Filter and Alerts Exist for VPC Network Changes",
		"description": _desc_2_10,
	}
}
