package tofuscan

import data.tofuscan.lib
import rego.v1

_desc_2_5 := concat("", [
	"Project ownership grants the highest privilege level in GCP. Log metric filters and ",
	"alerts on ownership assignment changes detect unauthorized privilege escalation in real time.",
])

# No log metric filter exists for project ownership changes.
deny contains violation if {
	input.resource.google_project
	not lib.metric_filter_exists("roles/owner")
	violation := {
		"resource": "global",
		"rule_id": "gcp/cis/2.5",
		"cis_control": "2.5",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure Log Metric Filter and Alerts Exist for Project Ownership Assignments/Changes",
		"description": _desc_2_5,
	}
}

# Log metric exists but no alert policy references it.
deny contains violation if {
	input.resource.google_project
	some _label, resources in input.resource.google_logging_metric
	some resource in resources
	contains(object.get(resource, "filter", ""), "roles/owner")
	metric_name := object.get(resource, "name", "")
	count(metric_name) > 0
	not lib.alert_exists_for_metric(metric_name)
	violation := {
		"resource": "global",
		"rule_id": "gcp/cis/2.5",
		"cis_control": "2.5",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure Log Metric Filter and Alerts Exist for Project Ownership Assignments/Changes",
		"description": _desc_2_5,
	}
}
