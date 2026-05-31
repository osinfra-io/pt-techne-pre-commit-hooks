package tofuscan

import rego.v1

_desc_2_1 := concat("", [
	"Cloud Audit Logs record admin activity and data access events across GCP services. ",
	"All three log types (ADMIN_READ, DATA_READ, DATA_WRITE) must be enabled for allServices ",
	"with no exempted members, ensuring complete audit coverage for compliance and incident response.",
])

_required_log_types := {"ADMIN_READ", "DATA_READ", "DATA_WRITE"}

# allServices audit config is missing one or more required log types.
deny contains violation if {
	some name, resources in input.resource.google_project_iam_audit_config
	some resource in resources
	resource.service == "allServices"
	log_configs := object.get(resource, "audit_log_config", [])
	existing_types := {config.log_type | some config in log_configs}
	count(_required_log_types - existing_types) > 0
	violation := {
		"resource": concat(".", ["google_project_iam_audit_config", name]),
		"rule_id": "gcp/cis/2.1",
		"cis_control": "2.1",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure That Cloud Audit Logging Is Configured Properly",
		"description": _desc_2_1,
	}
}

# audit_log_config block contains exempted members, reducing audit coverage.
deny contains violation if {
	some name, resources in input.resource.google_project_iam_audit_config
	some resource in resources
	log_configs := object.get(resource, "audit_log_config", [])
	some log_config in log_configs
	members := object.get(log_config, "exempted_members", [])
	count(members) > 0
	violation := {
		"resource": concat(".", ["google_project_iam_audit_config", name]),
		"rule_id": "gcp/cis/2.1",
		"cis_control": "2.1",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure That Cloud Audit Logging Is Configured Properly",
		"description": _desc_2_1,
	}
}
