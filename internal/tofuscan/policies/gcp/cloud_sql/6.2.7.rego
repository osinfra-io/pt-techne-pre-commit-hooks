package tofuscan

import rego.v1
import data.tofuscan.lib

_desc_6_2_7 := concat("", [
	"Setting log_min_duration_statement=-1 disables logging of statement durations. ",
	"Logging statement durations can inadvertently include query literals (including ",
	"sensitive parameter values) in log output. Disabling this prevents unintentional ",
	"data exposure through slow-query logs.",
])

deny contains violation if {
	some name, resources in input.resource.google_sql_database_instance
	some resource in resources
	lib.is_postgres(resource)
	some settings in resource.settings
	some flag in object.get(settings, "database_flags", [])
	flag.name == "log_min_duration_statement"
	flag.value != "-1"
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/6.2.7",
		"cis_control": "6.2.7",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure That the Log_min_duration_statement Database Flag for Cloud SQL PostgreSQL Instance Is Set to -1",
		"description": _desc_6_2_7,
	}
}
