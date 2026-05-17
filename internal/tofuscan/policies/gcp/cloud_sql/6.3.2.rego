package regofu

import rego.v1

_desc_6_3_2 := concat("", [
	"Cross-database ownership chaining allows users to access objects in other databases ",
	"by leveraging ownership chains across database boundaries. This can grant unintended ",
	"access and should be disabled unless explicitly required.",
])

deny contains violation if {
	some name, resources in input.resource.google_sql_database_instance
	some resource in resources
	startswith(object.get(resource, "database_version", ""), "SQLSERVER_")
	not _has_sql_flag(resource, "cross db ownership chaining", "off")
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/6.3.2",
		"cis_control": "6.3.2",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure That the cross db ownership chaining Database Flag for Cloud SQL SQL Server Instance Is Set to Off",
		"description": _desc_6_3_2,
	}
}

_has_sql_flag(resource, flag_name, flag_value) if {
	some settings in resource.settings
	some flag in object.get(settings, "database_flags", [])
	flag.name == flag_name
	flag.value == flag_value
}
