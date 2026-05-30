package tofuscan

import data.tofuscan.lib
import rego.v1

_desc_6_1_2 := concat("", [
	"Setting skip_show_database=on prevents non-privileged users from using SHOW DATABASES ",
	"to enumerate all databases on the instance. This reduces information disclosure that ",
	"could assist an attacker in targeting specific databases.",
])

deny contains violation if {
	some name, resources in input.resource.google_sql_database_instance
	some resource in resources
	lib.is_mysql(resource)
	not _has_sql_flag(resource, "skip_show_database", "on")
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/6.1.2",
		"cis_control": "6.1.2",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure Skip_show_database Database Flag for Cloud SQL MySQL Instance Is Set to On",
		"description": _desc_6_1_2,
	}
}

_has_sql_flag(resource, flag_name, flag_value) if {
	some settings in resource.settings
	some flag in object.get(settings, "database_flags", [])
	flag.name == flag_name
	flag.value == flag_value
}
