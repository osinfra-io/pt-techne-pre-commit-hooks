package regofu

import rego.v1

# ddl and all are acceptable; none, mod, and absent are insufficient.
_acceptable_log_statement := {"ddl", "all"}

_desc_6_2_4 := concat("", [
	"The log_statement flag controls which SQL statements are logged by PostgreSQL. ",
	"Setting it to ddl or all ensures that schema-level changes (CREATE, ALTER, DROP) ",
	"are captured, providing an audit trail for structural database modifications.",
])

deny contains violation if {
	some name, resources in input.resource.google_sql_database_instance
	some resource in resources
	startswith(object.get(resource, "database_version", ""), "POSTGRES_")
	not _has_acceptable_log_statement(resource)
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/6.2.4",
		"cis_control": "6.2.4",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure Log_statement Database Flag for Cloud SQL PostgreSQL Instance Is Set Appropriately",
		"description": _desc_6_2_4,
	}
}

_has_acceptable_log_statement(resource) if {
	some settings in resource.settings
	some flag in object.get(settings, "database_flags", [])
	flag.name == "log_statement"
	flag.value in _acceptable_log_statement
}
