package tofuscan

import rego.v1

import data.tofuscan.lib

_sa_admin_roles_1_9 := {"roles/iam.serviceAccountAdmin"}

_sa_user_roles_1_9 := {"roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator"}

_desc_1_9 := concat("", [
	"Separation of duties requires that no single principal holds both the Service ",
	"Account Admin role and a Service Account User or Token Creator role on the same ",
	"project, which together enable privilege escalation by impersonating service accounts.",
])

# [project, member] pairs granted a Service Account Admin role.
_sa_admin_pairs_1_9 contains [scope, member] if {
	some _label, resources in input.resource.google_project_iam_member
	some resource in resources
	resource.role in _sa_admin_roles_1_9
	scope := object.get(resource, "project", "")
	member := resource.member
	not lib.is_unresolved(member)
}

_sa_admin_pairs_1_9 contains [scope, member] if {
	some _label, resources in input.resource.google_project_iam_binding
	some resource in resources
	resource.role in _sa_admin_roles_1_9
	scope := object.get(resource, "project", "")
	some member in object.get(resource, "members", [])
	not lib.is_unresolved(member)
}

# [project, member] pairs granted a Service Account User/Token Creator role.
_sa_user_pairs_1_9 contains [scope, member] if {
	some _label, resources in input.resource.google_project_iam_member
	some resource in resources
	resource.role in _sa_user_roles_1_9
	scope := object.get(resource, "project", "")
	member := resource.member
	not lib.is_unresolved(member)
}

_sa_user_pairs_1_9 contains [scope, member] if {
	some _label, resources in input.resource.google_project_iam_binding
	some resource in resources
	resource.role in _sa_user_roles_1_9
	scope := object.get(resource, "project", "")
	some member in object.get(resource, "members", [])
	not lib.is_unresolved(member)
}

_sa_duty_collision_1_9 if {
	some pair in _sa_admin_pairs_1_9
	pair in _sa_user_pairs_1_9
}

deny contains violation if {
	_sa_duty_collision_1_9
	violation := {
		"resource": "global",
		"rule_id": "gcp/cis/1.9",
		"cis_control": "1.9",
		"profile_level": "Level 2",
		"severity": "Medium",
		"title": "Ensure That Separation of Duties Is Enforced While Assigning Service Account Related Roles to Users",
		"description": _desc_1_9,
	}
}
