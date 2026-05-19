package tofuscan

import rego.v1
import data.tofuscan.lib

_desc_6_3_1 := concat("", [
	"Disabling external scripts prevents execution of scripts in external languages such ",
	"as Python or R within the SQL Server engine. This capability can be exploited for ",
	"code execution and should be disabled unless explicitly required.",
])

deny contains violation if {
	some name, resources in input.resource.google_sql_database_instance
	some resource in resources
	lib.is_sqlserver(resource)
	not _has_sql_flag(resource, "external scripts enabled", "off")
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/6.3.1",
		"cis_control": "6.3.1",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure external scripts enabled Database Flag for Cloud SQL SQL Server Instance Is Set to Off",
		"description": _desc_6_3_1,
	}
}

_has_sql_flag(resource, flag_name, flag_value) if {
	some settings in resource.settings
	some flag in object.get(settings, "database_flags", [])
	flag.name == flag_name
	flag.value == flag_value
}
