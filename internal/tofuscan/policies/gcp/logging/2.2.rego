package tofuscan

import rego.v1

_desc_2_2 := concat("", [
	"A log sink exports copies of all log entries to a durable destination ",
	"(Cloud Storage, BigQuery, Pub/Sub) enabling long-term retention and SIEM integration.",
])

deny contains violation if {
	# Only check when scanning a project-setup layer (google_project present).
	input.resource.google_project
	not input.resource.google_logging_project_sink

	# no iteration needed — checks for resource type existence only
	violation := {
		"resource": "global",
		"rule_id": "gcp/cis/2.2",
		"cis_control": "2.2",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That Sinks Are Configured for All Log Entries",
		"description": _desc_2_2,
	}
}
