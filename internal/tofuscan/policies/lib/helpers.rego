package tofuscan.lib

import rego.v1

# is_public_cidr returns true for CIDR ranges that represent unrestricted
# internet access. Used by firewall policies (3.6, 3.7) to detect open
# ingress from any source.
is_public_cidr("0.0.0.0/0")

is_public_cidr("::/0")

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
	regex.match(`^[0-9]+$`, p)
	to_number(p) == target
}

port_covered(ports, target) if {
	some p in ports
	matches := regex.find_all_string_submatch_n(`^([0-9]+)-([0-9]+)$`, p, 1)
	count(matches) == 1
	to_number(matches[0][1]) <= target
	target <= to_number(matches[0][2])
}
