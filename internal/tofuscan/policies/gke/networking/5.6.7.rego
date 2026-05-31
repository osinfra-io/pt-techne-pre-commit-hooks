package tofuscan

import rego.v1

_desc_5_6_7 := concat("", [
	"Google-managed SSL certificates for GKE Ingress are automatically provisioned and ",
	"renewed by GCP, eliminating the risk of certificate expiry and manual key management. ",
	"Ingress resources that configure TLS without the ",
	"networking.gke.io/managed-certificates annotation rely on manually managed secrets.",
])

# kubernetes_manifest Ingress with TLS but no Google-managed certificate annotation.
deny contains violation if {
	some name, resources in input.resource.kubernetes_manifest
	some resource in resources
	resource.manifest.kind == "Ingress"
	spec := object.get(resource.manifest, "spec", {})
	tls := object.get(spec, "tls", [])
	count(tls) > 0
	metadata := object.get(resource.manifest, "metadata", {})
	annotations := object.get(metadata, "annotations", {})
	not annotations["networking.gke.io/managed-certificates"]
	violation := {
		"resource": concat(".", ["kubernetes_manifest", name]),
		"rule_id": "gke/cis/5.6.7",
		"cis_control": "5.6.7",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure use of Google-managed SSL Certificates",
		"description": _desc_5_6_7,
	}
}

# kubernetes_ingress_v1 with TLS but no Google-managed certificate annotation.
deny contains violation if {
	some name, resources in input.resource.kubernetes_ingress_v1
	some resource in resources
	metadata_list := object.get(resource, "metadata", [])
	count(metadata_list) > 0
	metadata := metadata_list[0]
	annotations := object.get(metadata, "annotations", {})
	spec_list := object.get(resource, "spec", [])
	count(spec_list) > 0
	spec := spec_list[0]
	tls := object.get(spec, "tls", [])
	count(tls) > 0
	not annotations["networking.gke.io/managed-certificates"]
	violation := {
		"resource": concat(".", ["kubernetes_ingress_v1", name]),
		"rule_id": "gke/cis/5.6.7",
		"cis_control": "5.6.7",
		"profile_level": "Level 1",
		"severity": "High",
		"title": "Ensure use of Google-managed SSL Certificates",
		"description": _desc_5_6_7,
	}
}
