package tofuscan

import rego.v1

import data.tofuscan.lib

_kms_admin_roles_1_12 := {"roles/cloudkms.admin"}

_kms_user_roles_1_12 := {
	"roles/cloudkms.cryptoKeyEncrypter",
	"roles/cloudkms.cryptoKeyDecrypter",
	"roles/cloudkms.cryptoKeyEncrypterDecrypter",
}

_desc_1_12 := concat("", [
	"Separation of duties requires that no single principal holds both the Cloud KMS ",
	"Admin role and a CryptoKey Encrypter/Decrypter role on the same key, which together ",
	"allow a principal to both manage and use a key, defeating key custody controls.",
])

# [crypto_key_id, member] pairs granted a Cloud KMS Admin role.
_kms_admin_pairs_1_12 contains [scope, member] if {
	some _label, resources in input.resource.google_kms_crypto_key_iam_member
	some resource in resources
	resource.role in _kms_admin_roles_1_12
	scope := object.get(resource, "crypto_key_id", "")
	member := resource.member
	not lib.is_unresolved(member)
}

_kms_admin_pairs_1_12 contains [scope, member] if {
	some _label, resources in input.resource.google_kms_crypto_key_iam_binding
	some resource in resources
	resource.role in _kms_admin_roles_1_12
	scope := object.get(resource, "crypto_key_id", "")
	some member in object.get(resource, "members", [])
	not lib.is_unresolved(member)
}

# [crypto_key_id, member] pairs granted a CryptoKey Encrypter/Decrypter role.
_kms_user_pairs_1_12 contains [scope, member] if {
	some _label, resources in input.resource.google_kms_crypto_key_iam_member
	some resource in resources
	resource.role in _kms_user_roles_1_12
	scope := object.get(resource, "crypto_key_id", "")
	member := resource.member
	not lib.is_unresolved(member)
}

_kms_user_pairs_1_12 contains [scope, member] if {
	some _label, resources in input.resource.google_kms_crypto_key_iam_binding
	some resource in resources
	resource.role in _kms_user_roles_1_12
	scope := object.get(resource, "crypto_key_id", "")
	some member in object.get(resource, "members", [])
	not lib.is_unresolved(member)
}

_kms_duty_collision_1_12 if {
	some pair in _kms_admin_pairs_1_12
	pair in _kms_user_pairs_1_12
}

deny contains violation if {
	_kms_duty_collision_1_12
	violation := {
		"resource": "global",
		"rule_id": "gcp/cis/1.12",
		"cis_control": "1.12",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure That Separation of Duties Is Enforced While Assigning KMS Related Roles to Users",
		"description": _desc_1_12,
	}
}
