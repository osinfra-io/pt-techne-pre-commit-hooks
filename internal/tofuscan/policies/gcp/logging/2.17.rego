package tofuscan

import rego.v1

_desc_2_17 := concat("", [
	"Enabling logging on HTTP(S) Load Balancers captures request details including ",
	"source IPs, URLs, and response codes. A non-zero sample rate ensures traffic is ",
	"recorded for visibility into request patterns, anomaly detection, and incident response.",
])

# log_config absent or enable is not true.
deny contains violation if {
	some name, resources in input.resource.google_compute_backend_service
	some resource in resources
	log_configs := object.get(resource, "log_config", [])
	not _logging_enabled(log_configs)
	violation := {
		"resource": concat(".", ["google_compute_backend_service", name]),
		"rule_id": "gcp/cis/2.17",
		"cis_control": "2.17",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure Logging is Enabled for HTTP(S) Load Balancer",
		"description": _desc_2_17,
	}
}

# log_config present and enabled but sample_rate is 0.
deny contains violation if {
	some name, resources in input.resource.google_compute_backend_service
	some resource in resources
	log_configs := object.get(resource, "log_config", [])
	some log_config in log_configs
	object.get(log_config, "enable", false) == true
	object.get(log_config, "sample_rate", 1) == 0
	violation := {
		"resource": concat(".", ["google_compute_backend_service", name]),
		"rule_id": "gcp/cis/2.17",
		"cis_control": "2.17",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure Logging is Enabled for HTTP(S) Load Balancer",
		"description": _desc_2_17,
	}
}

_logging_enabled(log_configs) if {
	some log_config in log_configs
	object.get(log_config, "enable", false) == true
}
