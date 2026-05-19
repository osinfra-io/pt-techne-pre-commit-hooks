package tofuscan

import rego.v1
import data.tofuscan.lib

_desc_6_3_5 := concat("", [
	"The remote access flag controls whether the SQL Server instance can execute stored ",
	"procedures on remote servers. Disabling remote access removes this attack vector and ",
	"prevents the instance from being used as a pivot point for lateral movement.",
])

deny contains violation if {
	some name, resources in input.resource.google_sql_database_instance
	some resource in resources
	lib.is_sqlserver(resource)
	not _has_sql_flag(resource, "remote access", "off")
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/6.3.5",
		"cis_control": "6.3.5",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure remote access Database Flag for Cloud SQL SQL Server Instance Is Set to Off",
		"description": _desc_6_3_5,
	}
}

_has_sql_flag(resource, flag_name, flag_value) if {
	some settings in resource.settings
	some flag in object.get(settings, "database_flags", [])
	flag.name == flag_name
	flag.value == flag_value
}
