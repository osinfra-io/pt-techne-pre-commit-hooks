package regofu

import rego.v1

_desc_6_3_7 := concat("", [
	"Contained databases authenticate users without requiring domain-level credentials, ",
	"which can bypass organizational authentication policies and allow privilege escalation ",
	"between contained and non-contained databases. This feature should be disabled.",
])

deny contains violation if {
	some name, resources in input.resource.google_sql_database_instance
	some resource in resources
	startswith(object.get(resource, "database_version", ""), "SQLSERVER_")
	not _has_sql_flag(resource, "contained database authentication", "off")
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/6.3.7",
		"cis_control": "6.3.7",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure That the contained database authentication Database Flag for Cloud SQL SQL Server Instance Is Set to Off",
		"description": _desc_6_3_7,
	}
}

_has_sql_flag(resource, flag_name, flag_value) if {
	some settings in resource.settings
	some flag in object.get(settings, "database_flags", [])
	flag.name == flag_name
	flag.value == flag_value
}
