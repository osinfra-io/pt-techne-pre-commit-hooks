package tofuscan

import rego.v1

_desc_2_4 := concat("", [
	"Retention policies with Bucket Lock prevent log data from being modified or deleted ",
	"before the retention period expires, protecting audit trails from tampering. ",
	"Note: this policy checks that any google_storage_bucket resources with a ",
	"retention_policy block have bucket lock enabled (is_locked = true). It does not ",
	"verify that all log-export destination buckets define a retention policy.",
])

deny contains violation if {
	some name, resources in input.resource.google_storage_bucket
	some resource in resources
	retention_policies := object.get(resource, "retention_policy", [])
	count(retention_policies) > 0
	retention := retention_policies[0]
	not object.get(retention, "is_locked", false) == true
	violation := {
		"resource": concat(".", ["google_storage_bucket", name]),
		"rule_id": "gcp/cis/2.4",
		"cis_control": "2.4",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure That Retention Policies on Cloud Storage Buckets Used for Exporting Logs Are Configured Using Bucket Lock",
		"description": _desc_2_4,
	}
}
