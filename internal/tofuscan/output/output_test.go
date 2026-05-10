package output

import (
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"pre-commit-hooks/internal/tofuscan/engine"
)

func TestTruncatePath(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		maxLen int
		want   string
	}{
		{
			name:   "short path unchanged",
			path:   "/home/user/main.tofu",
			maxLen: 80,
			want:   "/home/user/main.tofu",
		},
		{
			name:   "long path truncated",
			path:   "/home/brett/repositories/osinfra-io/platform-group/arche/pt-arche-google-kubernetes-engine/.terraform/modules/test.tests.default.gke_fleet_host_regional.test.helpers/child/helpers.tofu",
			maxLen: 80,
			want:   "/home/brett/repositories/osinfra-io/platform-group/arche/pt-arche-…/helpers.tofu",
		},
		{
			name:   "exact length unchanged",
			path:   "/a/b/c.tofu",
			maxLen: 11,
			want:   "/a/b/c.tofu",
		},
		{
			name:   "very small maxLen hard truncates",
			path:   "/a/very-long-filename.tofu",
			maxLen: 10,
			want:   "/a/very-l…",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := truncatePath(tc.path, tc.maxLen)
			if got != tc.want {
				t.Errorf("truncatePath(%q, %d)\n got: %q\nwant: %q", tc.path, tc.maxLen, got, tc.want)
			}
			visibleLen := utf8.RuneCountInString(got)
			if visibleLen > tc.maxLen {
				t.Errorf("visible length %d exceeds maxLen %d", visibleLen, tc.maxLen)
			}
		})
	}
}

func TestPrintSummary_IncludesPassedRules(t *testing.T) {
	ruleResources := getRuleResourceMap()
	if len(ruleResources) == 0 {
		t.Fatal("expected embedded policies to contain at least one rule")
	}

	violations := []engine.Violation{
		{RuleID: "gcp/cis/1.10", Severity: "High", File: "main.tofu"},
		{RuleID: "gcp/cis/1.10", Severity: "High", File: "main.tofu"},
		{RuleID: "gke/cis/5.6.4", Severity: "Medium", File: "cluster.tofu"},
	}
	skipped := []engine.Violation{{RuleID: "gcp/cis/1.7"}}

	// Build resource types that match all rules so the matching count equals the total.
	allResourceTypes := make(map[string]struct{})
	for _, resTypes := range ruleResources {
		for rt := range resTypes {
			allResourceTypes[rt] = struct{}{}
		}
	}

	out := captureStdout(t, func() {
		printSummary(violations, skipped, allResourceTypes)
	})

	wantPassed := len(ruleResources) - 3
	if wantPassed < 0 {
		wantPassed = 0
	}

	if !strings.Contains(out, "passed") {
		t.Fatalf("expected summary to include passed count, output: %s", out)
	}
	totalChecked := len(ruleResources)
	wantRatio := strconv.Itoa(wantPassed) + "/" + strconv.Itoa(totalChecked) + " rules passed"
	if !strings.Contains(out, wantRatio) {
		t.Fatalf("expected ratio %q, output: %s", wantRatio, out)
	}
	if !strings.Contains(out, "1 skipped") {
		t.Fatalf("expected skipped count, output: %s", out)
	}
	if !strings.Contains(out, "2 high") || !strings.Contains(out, "1 medium") {
		t.Fatalf("expected severity breakdown, output: %s", out)
	}
}

func TestPrint_NoViolationsNoResources(t *testing.T) {
	// When Print is called with no resource types, we cannot determine
	// whether rules were evaluated against matching resources or simply
	// never fired. The passed count must not appear in this case.
	out := captureStdout(t, func() {
		Print(nil, nil, nil)
	})

	if !strings.Contains(out, "No violations found") {
		t.Fatalf("expected no-violations message, output: %s", out)
	}
	if strings.Contains(out, "passed") {
		t.Fatalf("passed count should not appear when no resource types present, output: %s", out)
	}
}

func TestPrint_PassedCountMatchesOnlyRelevantRules(t *testing.T) {
	// When scanning code with only GKE resources, only GKE-related rules
	// should contribute to the passed count.
	gkeResourceTypes := map[string]struct{}{
		"google_container_cluster":   {},
		"google_container_node_pool": {},
	}

	out := captureStdout(t, func() {
		Print(nil, nil, gkeResourceTypes)
	})

	// Count how many rules target GKE resource types.
	ruleResources := getRuleResourceMap()
	wantMatching := 0
	for _, resTypes := range ruleResources {
		for rt := range resTypes {
			if _, ok := gkeResourceTypes[rt]; ok {
				wantMatching++
				break
			}
		}
	}

	if wantMatching == 0 {
		t.Fatal("expected at least one matching GKE rule")
	}

	wantRatio := strconv.Itoa(wantMatching) + "/" + strconv.Itoa(wantMatching) + " rules passed"
	if !strings.Contains(out, wantRatio) {
		t.Fatalf("expected %q in output, got: %s", wantRatio, out)
	}

	// Verify it's less than the total rule count.
	if wantMatching >= len(ruleResources) {
		t.Fatalf("GKE-only matching rules (%d) should be less than total (%d)", wantMatching, len(ruleResources))
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}

	oldStdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	fn()
	_ = w.Close()

	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}

	return string(b)
}
