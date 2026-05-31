package tofuscan.lib

import rego.v1

# is_public_cidr returns true for CIDR ranges that represent unrestricted
# internet access. Used by firewall policies (3.6, 3.7) to detect open
# ingress from any source.
is_public_cidr("0.0.0.0/0")

is_public_cidr("::/0")

# is_unresolved returns true when a field value is an unresolved HCL expression
# (e.g. "${module.core_helpers.labels}"). The engine only resolves var.* and
# local.* references; module.*, data.*, and each.* remain as literal strings
# beginning with "${". Policies skip these values to avoid flagging legitimate
# configurations whose value is supplied at apply time by a module output.
is_unresolved(value) if {
	is_string(value)
	startswith(value, "${")
}

# truthy normalizes the boolean-ish values that appear after HCL parsing. A field
# may arrive as a real boolean (true) or as a string ("true"/"TRUE"/"1"), for
# example instance metadata values, which are always strings in GCP. Using truthy
# avoids type errors from calling lower() on a boolean and avoids false positives
# from comparing a boolean against a string literal.
truthy(true)

truthy(value) if {
	is_string(value)
	lower(value) == "true"
}

truthy("1")

# policy_data_public returns true when a google_*_iam_policy policy_data JSON
# string grants a role to allUsers or allAuthenticatedUsers. policy_data is only
# inspected when it is a resolved, valid JSON string; unresolved references (which
# typically come from a data.google_iam_policy data source) are skipped. The check
# matches exact member values rather than a raw substring to avoid false positives
# from principals whose name merely contains "allUsers".
policy_data_public(policy_data) if {
	is_string(policy_data)
	not startswith(policy_data, "${")
	json.is_valid(policy_data)
	doc := json.unmarshal(policy_data)
	some binding in object.get(doc, "bindings", [])
	some member in object.get(binding, "members", [])
	member in {"allUsers", "allAuthenticatedUsers"}
}

# is_mysql / is_postgres / is_sqlserver identify the engine family of a
# google_sql_database_instance resource, used by Cloud SQL policies.
is_mysql(resource) if startswith(object.get(resource, "database_version", ""), "MYSQL_")

is_postgres(resource) if startswith(object.get(resource, "database_version", ""), "POSTGRES_")

is_sqlserver(resource) if startswith(object.get(resource, "database_version", ""), "SQLSERVER_")

# metric_filter_exists returns true when at least one google_logging_metric
# resource has a filter attribute containing the given key term. Used by CIS
# 2.5–2.12 policies to verify that a required log metric filter is defined.
metric_filter_exists(key_term) if {
	some _label, resources in input.resource.google_logging_metric
	some resource in resources
	contains(object.get(resource, "filter", ""), key_term)
}

# alert_exists_for_metric returns true when at least one
# google_monitoring_alert_policy has a condition_threshold filter referencing
# the given metric name via the metric.type token. The exact token format
# (metric.type="logging.googleapis.com/user/<name>") avoids false positives
# from similarly-named metrics. Used by CIS 2.5–2.12 policies to verify that
# an alerting policy exists for each required log metric.
alert_exists_for_metric(metric_name) if {
	some _label, resources in input.resource.google_monitoring_alert_policy
	some resource in resources
	some condition in object.get(resource, "conditions", [])
	some threshold in object.get(condition, "condition_threshold", [])
	contains(object.get(threshold, "filter", ""), concat("", ["metric.type=\"logging.googleapis.com/user/", metric_name, "\""]))
}

# port_covered returns true when target (a number) is matched by any entry in
# ports. Firewall port entries may be a single port ("22") or an inclusive
# range ("20-30"), so an exact-equality check alone misses ranges that span
# the sensitive port. Used by firewall policies (3.6, 3.7).
port_covered(ports, target) if {
	some p in ports
	is_number(p)
	p == target
}

port_covered(ports, target) if {
	some p in ports
	is_string(p)
	regex.match(`^[0-9]+$`, p)
	to_number(p) == target
}

port_covered(ports, target) if {
	some p in ports
	is_string(p)
	matches := regex.find_all_string_submatch_n(`^([0-9]+)-([0-9]+)$`, p, 1)
	count(matches) == 1
	to_number(matches[0][1]) <= target
	target <= to_number(matches[0][2])
}
