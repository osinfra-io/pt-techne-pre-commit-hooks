package regofu

import rego.v1

_desc_6_4 := concat("", [
	"All connections to Cloud SQL must be encrypted using SSL/TLS to protect ",
	"data in transit from eavesdropping and man-in-the-middle attacks.",
])

deny contains violation if {
	some name, resources in input.resource.google_sql_database_instance
	some resource in resources
	settings_arr := object.get(resource, "settings", [{}])
	some settings in settings_arr
	ip_config_arr := object.get(settings, "ip_configuration", [{}])
	some ip_config in ip_config_arr
	object.get(ip_config, "ssl_mode", "ALLOW_UNENCRYPTED_AND_ENCRYPTED") == "ALLOW_UNENCRYPTED_AND_ENCRYPTED"
	object.get(ip_config, "require_ssl", false) != true
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/6.4",
		"cis_control": "6.4",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That the Cloud SQL Database Instance Requires All Incoming Connections To Use SSL",
		"description": _desc_6_4,
	}
}
