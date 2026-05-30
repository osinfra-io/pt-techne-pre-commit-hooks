package tofuscan

import data.tofuscan.lib
import rego.v1

_desc_6_2_3 := concat("", [
	"Enabling log_disconnections causes PostgreSQL to log session termination details. ",
	"Combined with log_connections, this provides a complete picture of database session ",
	"activity for audit and anomaly detection purposes.",
])

deny contains violation if {
	some name, resources in input.resource.google_sql_database_instance
	some resource in resources
	lib.is_postgres(resource)
	not _has_pg_flag_on(resource, "log_disconnections")
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/6.2.3",
		"cis_control": "6.2.3",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure That the Log_disconnections Database Flag for Cloud SQL PostgreSQL Instance Is Set to On",
		"description": _desc_6_2_3,
	}
}

_has_pg_flag_on(resource, flag_name) if {
	some settings in resource.settings
	some flag in object.get(settings, "database_flags", [])
	flag.name == flag_name
	flag.value == "on"
}
