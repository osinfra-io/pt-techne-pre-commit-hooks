package regofu.lib

import rego.v1

# is_public_cidr returns true for CIDR ranges that represent unrestricted
# internet access. Used by firewall policies (3.6, 3.7) to detect open
# ingress from any source.
is_public_cidr("0.0.0.0/0")

is_public_cidr("::/0")
