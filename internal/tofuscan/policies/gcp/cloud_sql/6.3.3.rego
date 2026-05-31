package tofuscan

import data.tofuscan.lib
import rego.v1

_desc_6_3_3 := concat("", [
	"Setting user connections to a non-zero value limits the number of simultaneous ",
	"connections allowed per login, which can be exploited to cause a denial of service. ",
	"The flag should be absent or set to 0 (unlimited) to avoid connection-based DoS risks.",
])

deny contains violation if {
	some name, resources in input.resource.google_sql_database_instance
	some resource in resources
	lib.is_sqlserver(resource)
	some settings in resource.settings
	some flag in object.get(settings, "database_flags", [])
	flag.name == "user connections"
	flag.value != "0"
	violation := {
		"resource": concat(".", ["google_sql_database_instance", name]),
		"rule_id": "gcp/cis/6.3.3",
		"cis_control": "6.3.3",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure user Connections Database Flag for Cloud SQL SQL Server Instance Is Set to a Non-limiting Value",
		"description": _desc_6_3_3,
	}
}
