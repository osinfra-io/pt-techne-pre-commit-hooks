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
