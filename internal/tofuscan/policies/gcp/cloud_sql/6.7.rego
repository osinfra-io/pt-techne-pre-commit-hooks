package tofuscan

import rego.v1

_desc_6_7 := concat("", [
	"Automated backups ensure that a recovery point is available in the event of ",
	"data loss, corruption, or accidental deletion.",
])

deny contains violation if {
	some name, resources in input.resource.google_sql_database_instance
	some resource in resources
	some settings in resource.settings
	backup_configs := object.get(settings, "backup_configuration", [{}])
	some backup in backup_configs
	object.get(backup, "enabled", false) != true
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/6.7",
		"cis_control": "6.7",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure That Cloud SQL Database Instances Are Configured With Automated Backups",
		"description": _desc_6_7,
	}
}
