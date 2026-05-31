package tofuscan

import rego.v1

_secret_patterns := {
	"API_KEY",
	"AUTH",
	"CREDENTIAL",
	"PASSWD",
	"PASSWORD",
	"PRIVATE_KEY",
	"SECRET",
	"TOKEN",
}

_desc_1_18 := concat("", [
	"Cloud Functions environment variables are not encrypted and are visible in the GCP console. ",
	"Store secrets in Secret Manager and reference them via secret_environment_variables instead. ",
	"Note: this policy uses heuristic key-name matching and may produce false positives. ",
	"It cannot detect secrets stored under non-suspicious key names.",
])

_key_looks_like_secret(key) if {
	some pattern in _secret_patterns
	contains(upper(key), pattern)
}

# v1 Cloud Functions
deny contains violation if {
	some name, resources in input.resource.google_cloudfunctions_function
	some resource in resources
	env_vars := object.get(resource, "environment_variables", {})
	some key, _ in env_vars
	_key_looks_like_secret(key)
	violation := {
		"resource": concat(".", ["google_cloudfunctions_function", name]),
		"rule_id": "gcp/cis/1.18",
		"cis_control": "1.18",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure Secrets are Not Stored in Cloud Functions Environment Variables",
		"description": _desc_1_18,
	}
}

# v2 Cloud Functions — plain environment_variables in service_config
deny contains violation if {
	some name, resources in input.resource.google_cloudfunctions2_function
	some resource in resources
	service_configs := object.get(resource, "service_config", [])
	count(service_configs) > 0
	service_config := service_configs[0]
	env_vars := object.get(service_config, "environment_variables", {})
	some key, _ in env_vars
	_key_looks_like_secret(key)
	violation := {
		"resource": concat(".", ["google_cloudfunctions2_function", name]),
		"rule_id": "gcp/cis/1.18",
		"cis_control": "1.18",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure Secrets are Not Stored in Cloud Functions Environment Variables",
		"description": _desc_1_18,
	}
}
