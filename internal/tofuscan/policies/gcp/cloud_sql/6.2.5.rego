package tofuscan

import data.tofuscan.lib
import rego.v1

# Severity levels less strict than WARNING (more verbose / noisier).
_too_verbose_6_2_5 := {
	"DEBUG5", "DEBUG4", "DEBUG3", "DEBUG2", "DEBUG1",
	"INFO", "NOTICE",
	"debug5", "debug4", "debug3", "debug2", "debug1",
	"info", "notice",
}

_desc_6_2_5 := concat("", [
	"The log_min_messages flag sets the minimum message severity that PostgreSQL writes ",
	"to the server log. Setting it less strict than WARNING (e.g. DEBUG, INFO, NOTICE) ",
	"floods logs with routine messages, making it harder to identify security-relevant events.",
])

deny contains violation if {
	some name, resources in input.resource.google_sql_database_instance
	some resource in resources
	lib.is_postgres(resource)
	some settings in resource.settings
	some flag in object.get(settings, "database_flags", [])
	flag.name == "log_min_messages"
	flag.value in _too_verbose_6_2_5
	violation := {
		"resource": concat(".", ["google_sql_database_instance", name]),
		"rule_id": "gcp/cis/6.2.5",
		"cis_control": "6.2.5",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure that the Log_min_messages Flag for a Cloud SQL PostgreSQL Instance Is Set to Warning or Stricter",
		"description": _desc_6_2_5,
	}
}
