package tofuscan

import data.tofuscan.lib
import rego.v1

_desc_6_3_4 := concat("", [
	"The user options flag sets global default query-processing options for all user ",
	"sessions, which can override individual session settings and create unpredictable ",
	"behavior. It should not be configured.",
])

deny contains violation if {
	some name, resources in input.resource.google_sql_database_instance
	some resource in resources
	lib.is_sqlserver(resource)
	some settings in resource.settings
	some flag in object.get(settings, "database_flags", [])
	flag.name == "user options"
	violation := {
		"resource": concat(".", ["google_sql_database_instance", name]),
		"rule_id": "gcp/cis/6.3.4",
		"cis_control": "6.3.4",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure user options Database Flag for Cloud SQL SQL Server Instance Is Not Configured",
		"description": _desc_6_3_4,
	}
}
