package tofuscan

import data.tofuscan.lib
import rego.v1

_desc_6_1_3 := concat("", [
	"The local_infile flag enables loading data directly from client-side files into the ",
	"database. This capability can be exploited to read arbitrary files accessible to ",
	"the MySQL process. It should be disabled unless explicitly required.",
])

deny contains violation if {
	some name, resources in input.resource.google_sql_database_instance
	some resource in resources
	lib.is_mysql(resource)
	not _has_sql_flag(resource, "local_infile", "off")
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/6.1.3",
		"cis_control": "6.1.3",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That the Local_infile Database Flag for a Cloud SQL MySQL Instance Is Set to Off",
		"description": _desc_6_1_3,
	}
}

_has_sql_flag(resource, flag_name, flag_value) if {
	some settings in resource.settings
	some flag in object.get(settings, "database_flags", [])
	flag.name == flag_name
	flag.value == flag_value
}
