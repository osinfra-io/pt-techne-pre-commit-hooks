package tofuscan

import rego.v1

_desc_6_5 := concat("", [
	"Authorized Networks for Cloud SQL should not include 0.0.0.0/0, which would ",
	"allow connections from any IP address on the internet.",
])

deny contains violation if {
	some name, resources in input.resource.google_sql_database_instance
	some resource in resources
	some settings in resource.settings
	ip_configs := object.get(settings, "ip_configuration", [{}])
	some ip_config in ip_configs
	networks := object.get(ip_config, "authorized_networks", [])
	some network in networks
	network.value == "0.0.0.0/0"
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/6.5",
		"cis_control": "6.5",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That Cloud SQL Database Instances Do Not Implicitly Whitelist All Public IP Addresses",
		"description": _desc_6_5,
	}
}
