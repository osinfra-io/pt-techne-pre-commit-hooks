package regofu

import rego.v1

_sa_roles_1_6 := {
	"roles/iam.serviceAccountUser",
	"roles/iam.serviceAccountTokenCreator",
}

_desc_1_6 := concat("", [
	"The serviceAccountUser and serviceAccountTokenCreator roles grant the ability to ",
	"impersonate or create tokens for service accounts. Granting them at the project ",
	"level allows impersonation of any service account in the project. These roles ",
	"should be granted at the individual service account level only.",
])

deny contains violation if {
	some name, resources in input.resource.google_project_iam_member
	some resource in resources
	resource.role in _sa_roles_1_6
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/1.6",
		"cis_control": "1.6",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure That IAM Users Are Not Assigned the Service Account User or Service Account Token Creator Roles at Project Level",
		"description": _desc_1_6,
	}
}

deny contains violation if {
	some name, resources in input.resource.google_project_iam_binding
	some resource in resources
	resource.role in _sa_roles_1_6
	violation := {
		"resource": name,
		"rule_id": "gcp/cis/1.6",
		"cis_control": "1.6",
		"profile_level": "Level 1",
		"severity": "Medium",
		"title": "Ensure That IAM Users Are Not Assigned the Service Account User or Service Account Token Creator Roles at Project Level",
		"description": _desc_1_6,
	}
}
