package engine

import (
	"context"
	"os"
	"sort"
	"testing"

	"pre-commit-hooks/internal/tofuscan/policies"
)

func TestFailFixtureViolations(t *testing.T) {
	files := []string{"../../../test/tofuscan/fixtures/fail/main.tofu"}
	violations, err := Run(context.Background(), files, policies.FS)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Collect all rule_ids from violations.
	var got []string
	for _, v := range violations {
		got = append(got, v.RuleID)
	}
	sort.Strings(got)

	// Every policy should fire against the fail fixture.
	// gke/cis/5.7.1 fires twice (logging + monitoring are separate deny rules).
	// gcp/cis/5.1 fires twice (iam_member + iam_binding resources).
	expected := []string{
		"gcp/cis/1.10",
		"gcp/cis/1.5",
		"gcp/cis/1.7",
		"gcp/cis/2.2",
		"gcp/cis/3.3",
		"gcp/cis/3.4",
		"gcp/cis/3.6",
		"gcp/cis/3.7",
		"gcp/cis/3.8",
		"gcp/cis/4.1",
		"gcp/cis/4.11",
		"gcp/cis/4.2",
		"gcp/cis/4.3",
		"gcp/cis/4.5",
		"gcp/cis/4.6",
		"gcp/cis/4.8",
		"gcp/cis/4.9",
		"gcp/cis/5.1",
		"gcp/cis/5.1",
		"gcp/cis/5.2",
		"gcp/cis/6.4",
		"gcp/cis/6.5",
		"gcp/cis/6.6",
		"gcp/cis/6.7",
		"gcp/cis/7.1",
		"gke/cis/5.10.2",
		"gke/cis/5.10.4",
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
		"gke/cis/5.6.2",
		"gke/cis/5.6.3",
		"gke/cis/5.6.4",
		"gke/cis/5.6.5",
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
	files := []string{"../../../test/tofuscan/fixtures/pass/main.tofu"}
	violations, err := Run(context.Background(), files, policies.FS)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(violations) != 0 {
		for _, v := range violations {
			t.Errorf("unexpected violation: %s (%s) in resource %q", v.RuleID, v.Title, v.Resource)
		}
	}
}

func TestViolationFields(t *testing.T) {
	files := []string{"../../../test/tofuscan/fixtures/fail/main.tofu"}
	violations, err := Run(context.Background(), files, policies.FS)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, v := range violations {
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
		"vm1":    1,
		"bucket": 5,
		"vm2":    12,
	}
	for name, wantLine := range cases {
		if gotLine := index[name]; gotLine != wantLine {
			t.Errorf("resource %q: got line %d, want %d", name, gotLine, wantLine)
		}
	}

	// Non-existent resource returns 0.
	if line := index["nonexistent"]; line != 0 {
		t.Errorf("nonexistent resource: got line %d, want 0", line)
	}
}

func TestResourceLineIndexNonexistentFile(t *testing.T) {
	index := resourceLineIndex("/nonexistent/file.tofu")
	if len(index) != 0 {
		t.Errorf("expected empty index, got %v", index)
	}
}

func TestGlobalViolationFiresOnceAcrossFiles(t *testing.T) {
	// When scanning multiple files where none defines a log sink,
	// CIS 2.2 (global existence check) should fire exactly once,
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
	for _, v := range violations {
		if v.RuleID == "gcp/cis/2.2" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("gcp/cis/2.2 should fire exactly once across files, got %d", count)
	}
}

func TestGlobalViolationSuppressedWhenSinkExists(t *testing.T) {
	// When one file defines a log sink, CIS 2.2 should not fire
	// even if other files don't have one.
	files := []string{
		"../../../test/tofuscan/fixtures/fail/main.tofu",
		"../../../test/tofuscan/fixtures/pass/main.tofu",
	}
	violations, err := Run(context.Background(), files, policies.FS)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, v := range violations {
		if v.RuleID == "gcp/cis/2.2" {
			t.Error("gcp/cis/2.2 should not fire when a log sink exists in any scanned file")
		}
	}
}
