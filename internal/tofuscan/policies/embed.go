package policies

import "embed"

//go:embed all:gcp all:gke all:lib
var FS embed.FS
