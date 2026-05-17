package regofu

import rego.v1

# VERBOSE is less strict than DEFAULT; DEFAULT and TERSE are acceptable.
_verbose_values_6_2_1 := {"VERBOSE", "verbose"}

_desc_6_2_1 := concat("", [
	"The log_error_verbosity flag controls how much detail PostgreSQL includes in error ",
	"messages. Setting it to VERBOSE can expose internal state information that assists ",
	"attackers. DEFAULT or TERSE are acceptable settings.",
])

deny contains violation if {
	some name, resources in input.resource.google_sql_database_instance
	some resource in resources
	startswith(object.get(resource, "database_version", ""), "POSTGRES_")
	some settings in resource.settings
	some flag in object.get(settings, "database_flags", [])
	flag.name == "log_error_verbosity"
	flag.value in _verbose_values_6_2_1
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/6.2.1",
		"cis_control": "6.2.1",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure Log_error_verbosity Database Flag for Cloud SQL PostgreSQL Instance Is Set to Default or Stricter",
		"description": _desc_6_2_1,
	}
}
