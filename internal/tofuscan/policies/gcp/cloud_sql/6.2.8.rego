package tofuscan

import data.tofuscan.lib
import rego.v1

_desc_6_2_8 := concat("", [
	"The pgaudit extension provides detailed session and object audit logging for ",
	"PostgreSQL. Enabling cloudsql.enable_pgaudit activates pgaudit on the Cloud SQL ",
	"instance, producing audit logs required for compliance with standards like PCI DSS ",
	"and HIPAA.",
])

deny contains violation if {
	some name, resources in input.resource.google_sql_database_instance
	some resource in resources
	lib.is_postgres(resource)
	not _has_pg_flag_on(resource, "cloudsql.enable_pgaudit")
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/6.2.8",
		"cis_control": "6.2.8",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure That cloudsql.enable_pgaudit Database Flag for each Cloud SQL PostgreSQL Instance Is Set to On",
		"description": _desc_6_2_8,
	}
}

_has_pg_flag_on(resource, flag_name) if {
	some settings in resource.settings
	some flag in object.get(settings, "database_flags", [])
	flag.name == flag_name
	flag.value == "on"
}
