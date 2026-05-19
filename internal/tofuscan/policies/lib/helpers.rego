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
