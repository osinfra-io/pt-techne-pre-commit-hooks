package regofu

import rego.v1

# Severity levels less strict than ERROR.
_too_verbose_6_2_6 := {
	"DEBUG5", "DEBUG4", "DEBUG3", "DEBUG2", "DEBUG1",
	"INFO", "NOTICE", "WARNING",
	"debug5", "debug4", "debug3", "debug2", "debug1",
	"info", "notice", "warning",
}

_desc_6_2_6 := concat("", [
	"The log_min_error_statement flag controls the minimum severity level for which ",
	"PostgreSQL logs the SQL statement that caused the error. Setting it stricter than ",
	"ERROR ensures that the triggering statement is recorded for error analysis without ",
	"logging every warning-level statement.",
])

deny contains violation if {
	some name, resources in input.resource.google_sql_database_instance
	some resource in resources
	startswith(object.get(resource, "database_version", ""), "POSTGRES_")
	some settings in resource.settings
	some flag in object.get(settings, "database_flags", [])
	flag.name == "log_min_error_statement"
	flag.value in _too_verbose_6_2_6
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/6.2.6",
		"cis_control": "6.2.6",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure Log_min_error_statement Database Flag for Cloud SQL PostgreSQL Instance Is Set to Error or Stricter",
		"description": _desc_6_2_6,
	}
}
