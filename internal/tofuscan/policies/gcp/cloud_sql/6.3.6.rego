package tofuscan

import data.tofuscan.lib
import rego.v1

_desc_6_3_6 := concat("", [
	"Trace flag 3625 masks the details of SQL Server error messages shown to non-admin ",
	"users, replacing them with generic messages. This prevents information disclosure of ",
	"internal SQL Server state that could assist an attacker.",
])

deny contains violation if {
	some name, resources in input.resource.google_sql_database_instance
	some resource in resources
	lib.is_sqlserver(resource)
	not _has_sql_flag(resource, "3625", "on")
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/6.3.6",
		"cis_control": "6.3.6",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure 3625 (trace flag) Database Flag for all Cloud SQL Server Instances Is Set to On",
		"description": _desc_6_3_6,
	}
}

_has_sql_flag(resource, flag_name, flag_value) if {
	some settings in resource.settings
	some flag in object.get(settings, "database_flags", [])
	flag.name == flag_name
	flag.value == flag_value
}
