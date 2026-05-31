package tofuscan

import data.tofuscan.lib
import rego.v1

_desc_6_1_1 := concat("", [
	"The MySQL root account configured with host '%' or '' allows connections from any host, ",
	"granting unrestricted administrative access to the database instance. ",
	"Restrict the root account to a specific host or remove it entirely.",
])

deny contains violation if {
	some user_name, user_resources in input.resource.google_sql_user
	some user_resource in user_resources
	user_resource.name == "root"
	_open_host(user_resource)
	some _inst_label, inst_resources in input.resource.google_sql_database_instance
	some inst_resource in inst_resources
	lib.is_mysql(inst_resource)
	user_resource.instance == inst_resource.name
	violation := {
		"resource": concat(".", ["google_sql_user", user_name]),
		"rule_id": "gcp/cis/6.1.1",
		"cis_control": "6.1.1",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That a MySQL Instance Does Not Allow Anyone To Connect With Administrative Privileges",
		"description": _desc_6_1_1,
	}
}

_open_host(resource) if object.get(resource, "host", "") == "%"

_open_host(resource) if object.get(resource, "host", "") == ""
