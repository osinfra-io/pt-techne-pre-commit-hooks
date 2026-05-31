package tofuscan

import data.tofuscan.lib
import rego.v1

_desc_6_2_2 := concat("", [
	"Enabling log_connections causes PostgreSQL to log each successful client connection. ",
	"This provides an audit trail for access monitoring and supports detection of ",
	"unauthorized or anomalous connection patterns.",
])

deny contains violation if {
	some name, resources in input.resource.google_sql_database_instance
	some resource in resources
	lib.is_postgres(resource)
	not _has_pg_flag_on(resource, "log_connections")
	violation := {
		"resource": concat(".", ["google_sql_database_instance", name]),
		"rule_id": "gcp/cis/6.2.2",
		"cis_control": "6.2.2",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure That the Log_connections Database Flag for Cloud SQL PostgreSQL Instance Is Set to On",
		"description": _desc_6_2_2,
	}
}

_has_pg_flag_on(resource, flag_name) if {
	some settings in resource.settings
	some flag in object.get(settings, "database_flags", [])
	flag.name == flag_name
	flag.value == "on"
}
