package tofuscan

import rego.v1

_desc_6_6 := concat("", [
	"Cloud SQL instances should use private IP addresses only, accessible within ",
	"a VPC network, to avoid direct internet exposure.",
])

deny contains violation if {
	some name, resources in input.resource.google_sql_database_instance
	some resource in resources
	settings_arr := object.get(resource, "settings", [{}])
	some settings in settings_arr
	ip_config_arr := object.get(settings, "ip_configuration", [{}])
	some ip_config in ip_config_arr
	object.get(ip_config, "ipv4_enabled", true) == true
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/6.6",
		"cis_control": "6.6",
		"profile_level": "Level 2",
		"severity": "High",
		"title": "Ensure That Cloud SQL Database Instances Do Not Have Public IPs",
		"description": _desc_6_6,
	}
}
