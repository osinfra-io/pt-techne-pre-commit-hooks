package engine

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/open-policy-agent/conftest/parser"

	"pre-commit-hooks/internal/tofuscan/policies"
)

func TestFailFixtureViolations(t *testing.T) {
	files := []string{"../../../test/tofuscan/fixtures/fail/main.tofu"}
	result, err := Run(context.Background(), files, policies.FS)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Collect all rule_ids from violations.
	var got []string
	for _, v := range result.Violations {
		got = append(got, v.RuleID)
	}
	sort.Strings(got)

	// Every policy should fire against the fail fixture.
	// gke/cis/5.7.1 fires twice (logging + monitoring are separate deny rules).
	// gcp/cis/5.1 fires twice (iam_member + iam_binding resources).
	expected := []string{
		"gcp/cis/1.5",
		"gcp/cis/1.9",
		"gcp/cis/1.11",
		"gcp/cis/1.6",
		"gcp/cis/1.7",
		"gcp/cis/1.8",
		"gcp/cis/1.10",
		"gcp/cis/1.10",
		"gcp/cis/1.12",
		"gcp/cis/1.15",
		"gcp/cis/1.17",
		"gcp/cis/1.18",
		"gcp/cis/1.18",
		"gcp/cis/2.1",
		"gcp/cis/2.1",
		"gcp/cis/2.3",
		"gcp/cis/2.4",
		"gcp/cis/2.5",
		"gcp/cis/2.6",
		"gcp/cis/2.7",
		"gcp/cis/2.8",
		"gcp/cis/2.9",
		"gcp/cis/2.10",
		"gcp/cis/2.11",
		"gcp/cis/2.12",
		"gcp/cis/2.13",
		"gcp/cis/2.14",
		"gcp/cis/2.17",
		"gcp/cis/2.17",
		"gcp/cis/3.1",
		"gcp/cis/3.1",
		"gcp/cis/3.3",
		"gcp/cis/3.4",
		"gcp/cis/3.6",
		"gcp/cis/3.7",
		"gcp/cis/3.10",
		"gcp/cis/3.11",
		"gcp/cis/4.1",
		"gcp/cis/4.11",
		"gcp/cis/4.2",
		"gcp/cis/4.3",
		"gcp/cis/4.4",
		"gcp/cis/4.5",
		"gcp/cis/4.6",
		"gcp/cis/4.7",
		"gcp/cis/4.8",
		"gcp/cis/4.9",
		"gcp/cis/5.1",
		"gcp/cis/5.1",
		"gcp/cis/5.1",
		"gcp/cis/5.2",
		"gcp/cis/6.1.1",
		"gcp/cis/6.1.2",
		"gcp/cis/6.1.3",
		"gcp/cis/6.2.1",
		"gcp/cis/6.2.2",
		"gcp/cis/6.2.3",
		"gcp/cis/6.2.4",
		"gcp/cis/6.2.5",
		"gcp/cis/6.2.6",
		"gcp/cis/6.2.7",
		"gcp/cis/6.2.8",
		"gcp/cis/6.3.1",
		"gcp/cis/6.3.2",
		"gcp/cis/6.3.3",
		"gcp/cis/6.3.4",
		"gcp/cis/6.3.5",
		"gcp/cis/6.3.6",
		"gcp/cis/6.3.7",
		"gcp/cis/6.4",
		"gcp/cis/6.5",
		"gcp/cis/6.7",
		"gcp/cis/6.8",
		"gcp/cis/7.1",
		"gcp/cis/7.1",
		"gcp/cis/7.1",
		"gcp/cis/7.2",
		"gcp/cis/7.3",
		"gcp/cis/8.1",
		"gke/cis/5.1.1",
		"gke/cis/5.9.2",
		"gke/cis/5.9.2",
		"gke/cis/5.10.2",
		"gke/cis/5.10.3",
		"gke/cis/5.2.1",
		"gke/cis/5.3.1",
		"gke/cis/5.4.1",
		"gke/cis/5.5.1",
		"gke/cis/5.5.2",
		"gke/cis/5.5.3",
		"gke/cis/5.5.4",
		"gke/cis/5.5.5",
		"gke/cis/5.5.6",
		"gke/cis/5.5.7",
		"gke/cis/5.6.1",
		"gke/cis/5.6.2",
		"gke/cis/5.6.3",
		"gke/cis/5.6.4",
		"gke/cis/5.6.5",
		"gke/cis/5.6.7",
		"gke/cis/5.6.7",
		"gke/cis/5.7.1",
		"gke/cis/5.7.1",
		"gke/cis/5.8.1",
		"gke/cis/5.8.3",
	}

	if len(got) != len(expected) {
		t.Errorf("violation count mismatch: got %d, want %d", len(got), len(expected))
		t.Logf("got:      %v", got)
		t.Logf("expected: %v", expected)
	}

	// Build maps to compare.
	gotCounts := countStrings(got)
	expectedCounts := countStrings(expected)

	for id, wantN := range expectedCounts {
		if gotN := gotCounts[id]; gotN != wantN {
			t.Errorf("rule %s: got %d violation(s), want %d", id, gotN, wantN)
		}
	}
	for id, gotN := range gotCounts {
		if _, ok := expectedCounts[id]; !ok {
			t.Errorf("unexpected violation for rule %s (%d occurrence(s))", id, gotN)
		}
	}
}

func TestPassFixtureNoViolations(t *testing.T) {
	fixtureDir := "../../../test/tofuscan/fixtures/pass"
	files, err := filepath.Glob(fixtureDir + "/*.tofu")
	if err != nil || len(files) == 0 {
		t.Fatalf("could not find fixture files: %v", err)
	}
	result, err := Run(context.Background(), files, policies.FS)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Violations) != 0 {
		for _, v := range result.Violations {
			t.Errorf("unexpected violation: %s (%s) in resource %q", v.RuleID, v.Title, v.Resource)
		}
	}
}

func TestViolationFields(t *testing.T) {
	files := []string{"../../../test/tofuscan/fixtures/fail/main.tofu"}
	result, err := Run(context.Background(), files, policies.FS)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, v := range result.Violations {
		if v.File == "" && v.Resource != "global" {
			t.Error("violation has empty File")
		}
		if v.Resource == "" {
			t.Errorf("violation %s has empty Resource", v.RuleID)
		}
		if v.RuleID == "" {
			t.Error("violation has empty RuleID")
		}
		if v.CISControl == "" {
			t.Errorf("violation %s has empty CISControl", v.RuleID)
		}
		if v.ProfileLevel == "" {
			t.Errorf("violation %s has empty ProfileLevel", v.RuleID)
		}
		if v.Severity == "" {
			t.Errorf("violation %s has empty Severity", v.RuleID)
		}
		if v.Title == "" {
			t.Errorf("violation %s has empty Title", v.RuleID)
		}
		if v.Description == "" {
			t.Errorf("violation %s has empty Description", v.RuleID)
		}
		if v.Severity != "High" && v.Severity != "Medium" {
			t.Errorf("violation %s has unexpected Severity %q", v.RuleID, v.Severity)
		}
	}
}

func TestFirewallPortRangeViolations(t *testing.T) {
	// CIS 3.6 (SSH/22) and 3.7 (RDP/3389) must fire when the open port is
	// expressed as an inclusive range that spans the sensitive port, not just
	// as an exact port string.
	content := `resource "google_compute_firewall" "ssh_range" {
  name    = "allow-ssh-range"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["20-30"]
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "rdp_range" {
  name    = "allow-rdp-range"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["3000-4000"]
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "unrelated_range" {
  name    = "allow-https-range"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["8000-9000"]
  }

  source_ranges = ["0.0.0.0/0"]
}
`
	tmp := t.TempDir()
	file := tmp + "/main.tofu"
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Run(context.Background(), []string{file}, policies.FS)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := map[string][]string{}
	for _, v := range result.Violations {
		got[v.RuleID] = append(got[v.RuleID], v.Resource)
	}

	if res := got["gcp/cis/3.6"]; len(res) != 1 || res[0] != "google_compute_firewall.ssh_range" {
		t.Errorf("gcp/cis/3.6: got %v, want [google_compute_firewall.ssh_range]", res)
	}
	if res := got["gcp/cis/3.7"]; len(res) != 1 || res[0] != "google_compute_firewall.rdp_range" {
		t.Errorf("gcp/cis/3.7: got %v, want [google_compute_firewall.rdp_range]", res)
	}
}

func countStrings(ss []string) map[string]int {
	m := make(map[string]int)
	for _, s := range ss {
		m[s]++
	}
	return m
}

func TestResourceLineIndex(t *testing.T) {
	content := `resource "google_compute_instance" "vm1" {
  name = "vm1"
}

resource "google_storage_bucket" "bucket" {
  name = "my-bucket"
}

# not a resource line
variable "project" {}

resource "google_compute_instance" "vm2" {
  name = "vm2"
}
`
	tmp := t.TempDir()
	f := tmp + "/test.tofu"
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	index := resourceLineIndex(f)

	cases := map[string]int{
		"google_compute_instance.vm1":    1,
		"google_storage_bucket.bucket":   5,
		"google_compute_instance.vm2":    12,
	}
	for name, wantLine := range cases {
		if gotLine := index[name]; gotLine != wantLine {
			t.Errorf("resource %q: got line %d, want %d", name, gotLine, wantLine)
		}
	}

	// Non-existent resource returns 0.
	if line := index["google_compute_instance.nonexistent"]; line != 0 {
		t.Errorf("nonexistent resource: got line %d, want 0", line)
	}
}

func TestResourceLineIndexNonexistentFile(t *testing.T) {
	index := resourceLineIndex("/nonexistent/file.tofu")
	if len(index) != 0 {
		t.Errorf("expected empty index, got %v", index)
	}
}

func TestResourceLineIndexSameLabelDifferentTypes(t *testing.T) {
	// Two resources share the label "this" but have different types.
	// Each must resolve to its own correct line number.
	content := `resource "google_compute_instance" "this" {
  name = "vm"
}

resource "google_storage_bucket" "this" {
  name = "bucket"
}
`
	tmp := t.TempDir()
	f := tmp + "/test.tofu"
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	index := resourceLineIndex(f)

	if got := index["google_compute_instance.this"]; got != 1 {
		t.Errorf("google_compute_instance.this: got line %d, want 1", got)
	}
	if got := index["google_storage_bucket.this"]; got != 5 {
		t.Errorf("google_storage_bucket.this: got line %d, want 5", got)
	}
}


func TestGlobalViolationFiresOnceAcrossFiles(t *testing.T) {
	// When scanning multiple files where none defines a log sink,
	// CIS 2.3 (global existence check) should fire exactly once,
	// not once per file.
	files := []string{
		"../../../test/tofuscan/fixtures/fail/main.tofu",
		"../../../test/tofuscan/fixtures/fail/main.tofu",
	}
	violations, err := Run(context.Background(), files, policies.FS)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int
	for _, v := range violations.Violations {
		if v.RuleID == "gcp/cis/2.3" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("gcp/cis/2.3 should fire exactly once across files, got %d", count)
	}
}

func TestGlobalViolationSuppressedWhenSinkExists(t *testing.T) {
	// When one file defines a log sink, CIS 2.3 should not fire
	// even if other files don't have one.
	files := []string{
		"../../../test/tofuscan/fixtures/fail/main.tofu",
		"../../../test/tofuscan/fixtures/pass/main.tofu",
	}
	violations, err := Run(context.Background(), files, policies.FS)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, v := range violations.Violations {
		if v.RuleID == "gcp/cis/2.3" {
			t.Error("gcp/cis/2.3 should not fire when a log sink exists in any scanned file")
		}
	}
}

func TestNormalizeConfigResolvesVariableAndLocalReferences(t *testing.T) {
	content := `variable "release_channel" {
  default = "REGULAR"
}

locals {
  networking_mode = "VPC_NATIVE"
}

resource "google_container_cluster" "primary" {
  networking_mode = local.networking_mode

  release_channel {
    channel = var.release_channel
  }
}
`

	tmp := t.TempDir()
	file := tmp + "/main.tofu"
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	configs, err := parser.ParseConfigurationsAs([]string{file}, "hcl2")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	dirSymbols := buildDirSymbolTables([]string{file})
	normalized := normalizeConfig(file, configs[file], dirSymbols)
	resource := normalized.(map[string]interface{})["resource"].(map[string]interface{})
	clusters := resource["google_container_cluster"].(map[string]interface{})
	cluster := clusters["primary"].([]interface{})[0].(map[string]interface{})

	if got := cluster["networking_mode"]; got != "VPC_NATIVE" {
		t.Fatalf("networking_mode: got %#v, want %q", got, "VPC_NATIVE")
	}

	releaseChannel := cluster["release_channel"].([]interface{})[0].(map[string]interface{})
	if got := releaseChannel["channel"]; got != "REGULAR" {
		t.Fatalf("release_channel.channel: got %#v, want %q", got, "REGULAR")
	}
}

// TestDynamicBlockExpansionWithLocalFunctions covers the false-positive pattern
// seen in the pt-arche-google-cloud-sql module, where database_flags are
// defined via concat() and startswith() in locals.tofu, then used in a dynamic
// block in main.tofu. Both the function evaluation and dynamic block expansion
// must work together to avoid false-positive CIS 6.2.x violations.
func TestDynamicBlockExpansionWithLocalFunctions(t *testing.T) {
	tmp := t.TempDir()

	variablesContent := `variable "database_version" {
  default = "POSTGRES_16"
  type    = string
}

variable "postgres_database_flags" {
  default = []
  type = list(object({
    name  = string
    value = string
  }))
}
`

	localsContent := `locals {
  postgres_database_flags = concat([
    {
      name  = "log_connections"
      value = "on"
    },
    {
      name  = "log_disconnections"
      value = "on"
    },
  ], var.postgres_database_flags)

  database_flags = startswith(var.database_version, "POSTGRES_") ? local.postgres_database_flags : []
}
`

	mainContent := `resource "google_sql_database_instance" "this" {
  database_version = var.database_version

  settings {
    dynamic "database_flags" {
      for_each = local.database_flags
      content {
        name  = database_flags.value.name
        value = database_flags.value.value
      }
    }

    tier = "db-n1-standard-1"
  }
}
`

	variablesFile := tmp + "/variables.tofu"
	localsFile := tmp + "/locals.tofu"
	mainFile := tmp + "/main.tofu"

	for path, content := range map[string]string{
		variablesFile: variablesContent,
		localsFile:    localsContent,
		mainFile:      mainContent,
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	result, err := Run(context.Background(), []string{variablesFile, localsFile, mainFile}, policies.FS)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// CIS 6.2.2 (log_connections) and 6.2.3 (log_disconnections) must not fire.
	for _, v := range result.Violations {
		if v.RuleID == "gcp/cis/6.2.2" || v.RuleID == "gcp/cis/6.2.3" {
			t.Errorf("false positive: %s fired on resource with dynamic database_flags via locals", v.RuleID)
		}
	}
}

// TestExpandDynamicBlocksMaterialisesContent verifies that expandDynamicBlocks
// resolves "<blockName>.value.<attr>" references in the content template rather
// than using the for_each items verbatim. This covers cases where content
// renames or restructures the iterator value.
func TestExpandDynamicBlocksMaterialisesContent(t *testing.T) {
	input := map[string]interface{}{
		"dynamic": map[string]interface{}{
			"tag": []interface{}{
				map[string]interface{}{
					"for_each": []interface{}{
						map[string]interface{}{"k": "env", "v": "prod"},
						map[string]interface{}{"k": "team", "v": "platform"},
					},
					"content": []interface{}{
						map[string]interface{}{
							"key":   "${tag.value.k}",
							"value": "${tag.value.v}",
						},
					},
				},
			},
		},
	}

	got := expandDynamicBlocks(input).(map[string]interface{})
	tags, ok := got["tag"].([]interface{})
	if !ok {
		t.Fatalf("expected tag to be []interface{}, got %T", got["tag"])
	}
	if len(tags) != 2 {
		t.Fatalf("expected 2 tag entries, got %d", len(tags))
	}

	want := []map[string]interface{}{
		{"key": "env", "value": "prod"},
		{"key": "team", "value": "platform"},
	}
	for i, entry := range tags {
		m, ok := entry.(map[string]interface{})
		if !ok {
			t.Fatalf("tag[%d]: expected map, got %T", i, entry)
		}
		for k, wantV := range want[i] {
			if got := m[k]; got != wantV {
				t.Errorf("tag[%d][%q]: got %v, want %v", i, k, got, wantV)
			}
		}
	}

	if _, hasDynamic := got["dynamic"]; hasDynamic {
		t.Error("dynamic key should have been removed after expansion")
	}
}

func TestNormalizeConfigResolvesReferencesAcrossFiles(t *testing.T) {
	tmp := t.TempDir()

	variables := `variable "release_channel" {
  default = "REGULAR"
}
`
	locals := `locals {
  networking_mode = "VPC_NATIVE"
}
`
	main := `resource "google_container_cluster" "primary" {
  networking_mode = local.networking_mode

  release_channel {
    channel = var.release_channel
  }
}
`

	variablesFile := tmp + "/variables.tofu"
	localsFile := tmp + "/locals.tofu"
	mainFile := tmp + "/main.tofu"

	for path, content := range map[string]string{
		variablesFile: variables,
		localsFile:    locals,
		mainFile:      main,
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	files := []string{variablesFile, localsFile, mainFile}
	configs, err := parser.ParseConfigurationsAs(files, "hcl2")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	dirSymbols := buildDirSymbolTables(files)
	normalized := normalizeConfig(mainFile, configs[mainFile], dirSymbols)
	resource := normalized.(map[string]interface{})["resource"].(map[string]interface{})
	clusters := resource["google_container_cluster"].(map[string]interface{})
	cluster := clusters["primary"].([]interface{})[0].(map[string]interface{})

	if got := cluster["networking_mode"]; got != "VPC_NATIVE" {
		t.Fatalf("networking_mode across files: got %#v, want %q", got, "VPC_NATIVE")
	}

	releaseChannel := cluster["release_channel"].([]interface{})[0].(map[string]interface{})
	if got := releaseChannel["channel"]; got != "REGULAR" {
		t.Fatalf("release_channel.channel across files: got %#v, want %q", got, "REGULAR")
	}
}
