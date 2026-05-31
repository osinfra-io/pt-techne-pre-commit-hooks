package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSkipComment(t *testing.T) {
	cases := []struct {
		line        string
		wantControl string
		wantReason  string
	}{
		{"# tofu-scan skip: CIS 5.6.4 - Not needed", "5.6.4", "Not needed"},
		{"# tofu-scan skip: CIS 1.5", "1.5", ""},
		{"#tofu-scan skip: CIS 3.3 - reason", "3.3", "reason"},
		{"  # tofu-scan skip: CIS 5.5.1 - reason here", "5.5.1", "reason here"},
		{"# TOFU-SCAN SKIP: CIS 5.6.4 - case insensitive", "5.6.4", "case insensitive"},
		{"# tofu-scan skip: cis 5.6.4", "5.6.4", ""},
		{"# tofu-scan skip: CIS 5.6.4 -no space", "5.6.4", "no space"},
		// Not a skip comment.
		{"# regular comment", "", ""},
		{"resource \"a\" \"b\" {}", "", ""},
		{"", "", ""},
		{"# tofu-scan skip:", "", ""},
		{"# tofu-scan skip: CIS", "", ""},
		{"# tofu-scan skip: CIS ", "", ""},
		{"# tofu-scan skip: NOTCIS 5.6.4", "", ""},
	}
	for _, tc := range cases {
		control, reason := parseSkipComment(tc.line)
		if control != tc.wantControl || reason != tc.wantReason {
			t.Errorf("parseSkipComment(%q) = (%q, %q), want (%q, %q)",
				tc.line, control, reason, tc.wantControl, tc.wantReason)
		}
	}
}

func TestParseFileSkips(t *testing.T) {
	content := `# tofu-scan skip: CIS 1.5 - outside resource, ignored

variable "project" {}

resource "google_container_cluster" "primary" {
  # tofu-scan skip: CIS 5.5.1 - inside resource
  # tofu-scan skip: CIS 5.6.4 - also inside resource
  name = "test"
}

resource "google_compute_firewall" "allow" {
  name = "allow"
}
`
	tmp := t.TempDir()
	f := filepath.Join(tmp, "test.tofu")
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	resourceLevel := parseFileSkips(f)

	// Resource "google_container_cluster.primary": CIS 5.5.1 + CIS 5.6.4 (both inside block)
	primarySkips := resourceLevel["google_container_cluster.primary"]
	if primarySkips == nil {
		t.Fatal("expected resource-level skips for 'google_container_cluster.primary'")
	}
	if _, ok := primarySkips["5.5.1"]; !ok {
		t.Error("expected skip for CIS 5.5.1 on resource 'google_container_cluster.primary'")
	}
	if _, ok := primarySkips["5.6.4"]; !ok {
		t.Error("expected skip for CIS 5.6.4 on resource 'google_container_cluster.primary'")
	}
	if len(primarySkips) != 2 {
		t.Errorf("expected 2 skips for 'google_container_cluster.primary', got %d: %v", len(primarySkips), primarySkips)
	}

	// Resource "google_compute_firewall.allow": no skips
	if allowSkips := resourceLevel["google_compute_firewall.allow"]; len(allowSkips) != 0 {
		t.Errorf("expected no skips for 'google_compute_firewall.allow', got %v", allowSkips)
	}
}

func TestParseFileSkipsOutsideResourceIgnored(t *testing.T) {
	content := `# tofu-scan skip: CIS 2.2 - outside resource, should be ignored

resource "a" "first" {
  name = "first"
}

# tofu-scan skip: CIS 3.3 - between resources, should be ignored

resource "b" "second" {
  name = "second"
}
`
	tmp := t.TempDir()
	f := filepath.Join(tmp, "test.tofu")
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	resourceLevel := parseFileSkips(f)

	if firstSkips := resourceLevel["a.first"]; len(firstSkips) != 0 {
		t.Errorf("expected no skips for 'a.first', got %v", firstSkips)
	}
	if secondSkips := resourceLevel["b.second"]; len(secondSkips) != 0 {
		t.Errorf("expected no skips for 'b.second', got %v", secondSkips)
	}
}

func TestFilterSkipped(t *testing.T) {
	violations := []Violation{
		{File: "a.tofu", Resource: "google_container_cluster.primary", CISControl: "5.6.4", RuleID: "gke/cis/5.6.4"},
		{File: "a.tofu", Resource: "google_container_cluster.primary", CISControl: "5.5.1", RuleID: "gke/cis/5.5.1"},
		{File: "a.tofu", Resource: "google_compute_firewall.allow", CISControl: "3.3", RuleID: "gcp/cis/3.3"},
		{File: "", Resource: "global", CISControl: "2.2", RuleID: "gcp/cis/2.2"},
	}

	sd := &SkipDirectives{
		resourceLevel: map[string]map[string]map[string]string{
			"a.tofu": {
				"google_container_cluster.primary": {"5.6.4": "not needed"},
			},
		},
	}

	kept, skipped := sd.Filter(violations)

	if len(kept) != 3 {
		t.Errorf("expected 3 kept violations, got %d", len(kept))
	}
	if len(skipped) != 1 {
		t.Errorf("expected 1 skipped violation, got %d", len(skipped))
	}

	// Skipped: only 5.6.4 on "primary"
	if len(skipped) > 0 && skipped[0].CISControl != "5.6.4" {
		t.Errorf("expected skipped violation for CIS 5.6.4, got %s", skipped[0].CISControl)
	}
}

func TestParseFileSkipsNonexistentFile(t *testing.T) {
	resourceLevel := parseFileSkips("/nonexistent/file.tofu")
	if len(resourceLevel) != 0 {
		t.Errorf("expected empty results for nonexistent file")
	}
}

func TestParseFileSkipsNestedBraces(t *testing.T) {
	content := `resource "google_container_cluster" "primary" {
  # tofu-scan skip: CIS 5.6.4 - inside resource
  name = "test"
  node_config {
    metadata = {}
  }
}
`
	tmp := t.TempDir()
	f := filepath.Join(tmp, "test.tofu")
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	resourceLevel := parseFileSkips(f)

	primarySkips := resourceLevel["google_container_cluster.primary"]
	if primarySkips == nil || len(primarySkips) != 1 {
		t.Fatalf("expected 1 skip for 'google_container_cluster.primary', got %v", primarySkips)
	}
	if _, ok := primarySkips["5.6.4"]; !ok {
		t.Error("expected skip for CIS 5.6.4 on 'google_container_cluster.primary'")
	}
}

func TestParseFileSkipsBracesInComments(t *testing.T) {
	content := `resource "google_container_cluster" "primary" {
  # This comment has { extra braces }
  # tofu-scan skip: CIS 5.6.4 - Should apply to primary
  name = "test"
}

resource "google_storage_bucket" "bucket" {
  # tofu-scan skip: CIS 3.3 - Should apply to bucket
  name = "my-bucket"
}
`
	tmp := t.TempDir()
	f := filepath.Join(tmp, "test.tofu")
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	resourceLevel := parseFileSkips(f)

	primarySkips := resourceLevel["google_container_cluster.primary"]
	if primarySkips == nil || len(primarySkips) != 1 {
		t.Fatalf("expected 1 skip for 'google_container_cluster.primary', got %v", primarySkips)
	}
	if _, ok := primarySkips["5.6.4"]; !ok {
		t.Error("expected skip for CIS 5.6.4 on 'google_container_cluster.primary'")
	}

	bucketSkips := resourceLevel["google_storage_bucket.bucket"]
	if bucketSkips == nil || len(bucketSkips) != 1 {
		t.Fatalf("expected 1 skip for 'google_storage_bucket.bucket', got %v", bucketSkips)
	}
	if _, ok := bucketSkips["3.3"]; !ok {
		t.Error("expected skip for CIS 3.3 on 'google_storage_bucket.bucket'")
	}
}

func TestCountBraces(t *testing.T) {
	cases := []struct {
		line string
		want int
	}{
		{`resource "a" "b" {`, 1},
		{`}`, -1},
		{`  metadata = {}`, 0},
		{`  # comment with { braces }`, 0},
		{`  // comment with { braces }`, 0},
		{`  name = "value with { braces }"`, 0},
		{`  name = "escaped \" still { in string"`, 0},
		{`  block { # comment with }`, 1},
		{`  name = "}"`, 0},
	}
	for _, tc := range cases {
		got := countBraces(tc.line)
		if got != tc.want {
			t.Errorf("countBraces(%q) = %d, want %d", tc.line, got, tc.want)
		}
	}
}

func TestParseFileSkipsSameLabelDifferentTypes(t *testing.T) {
	// Two resources share the label "this" but have different types.
	// A skip inside one block must not apply to the other.
	content := `resource "google_container_cluster" "this" {
  # tofu-scan skip: CIS 5.6.4 - cluster skip
  name = "cluster"
}

resource "google_storage_bucket" "this" {
  name = "bucket"
}
`
	tmp := t.TempDir()
	f := filepath.Join(tmp, "test.tofu")
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	resourceLevel := parseFileSkips(f)

	clusterSkips := resourceLevel["google_container_cluster.this"]
	if clusterSkips == nil || len(clusterSkips) != 1 {
		t.Fatalf("expected 1 skip for 'google_container_cluster.this', got %v", clusterSkips)
	}
	if _, ok := clusterSkips["5.6.4"]; !ok {
		t.Error("expected skip for CIS 5.6.4 on 'google_container_cluster.this'")
	}

	bucketSkips := resourceLevel["google_storage_bucket.this"]
	if len(bucketSkips) != 0 {
		t.Errorf("expected no skips for 'google_storage_bucket.this', got %v", bucketSkips)
	}
}
