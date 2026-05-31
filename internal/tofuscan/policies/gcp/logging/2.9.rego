package tofuscan

import data.tofuscan.lib
import rego.v1

_desc_2_9 := concat("", [
	"VPC route changes can redirect traffic to malicious destinations or expose internal ",
	"services. A metric filter and alert on gce_route changes enables detection of routing anomalies.",
])

# No log metric filter exists for VPC network route changes.
deny contains violation if {
	input.resource.google_project
	not lib.metric_filter_exists("gce_route")
	violation := {
		"resource": "global",
		"rule_id": "gcp/cis/2.9",
		"cis_control": "2.9",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure That the Log Metric Filter and Alerts Exist for VPC Network Route Changes",
		"description": _desc_2_9,
	}
}

# Log metric exists but no alert policy references it.
deny contains violation if {
	input.resource.google_project
	some _label, resources in input.resource.google_logging_metric
	some resource in resources
	contains(object.get(resource, "filter", ""), "gce_route")
	metric_name := object.get(resource, "name", "")
	count(metric_name) > 0
	not lib.alert_exists_for_metric(metric_name)
	violation := {
		"resource": "global",
		"rule_id": "gcp/cis/2.9",
		"cis_control": "2.9",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure That the Log Metric Filter and Alerts Exist for VPC Network Route Changes",
		"description": _desc_2_9,
	}
}
