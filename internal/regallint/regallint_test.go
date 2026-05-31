package regallint

import (
	"os"
	"path/filepath"
	"testing"

	"pre-commit-hooks/internal/testutil"
)

func TestRunRegalLint_Clean(t *testing.T) {
	testutil.SkipIfRegalNotInstalled(t)
	tempDir, cleanup := testutil.CreateTempDir(t, "regallint_clean")
	defer cleanup()

	// Create a subdirectory matching the package name to satisfy directory-package-mismatch.
	policyDir := filepath.Join(tempDir, "example")
	if err := os.Mkdir(policyDir, 0755); err != nil {
		t.Fatalf("Failed to create policy dir: %v", err)
	}

	// Use a minimal, properly formatted policy with no violations.
	policy := "package example\n\nimport rego.v1\n"
	filePath := filepath.Join(policyDir, "policy.rego")
	if err := os.WriteFile(filePath, []byte(policy), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	out, err := RunRegalLint([]string{filePath})
	if err != nil {
		t.Fatalf("Expected clean policy to pass regal lint, got error: %v\nOutput: %s", err, out)
	}
}

func TestRunRegalLint_Violations(t *testing.T) {
	testutil.SkipIfRegalNotInstalled(t)
	tempDir, cleanup := testutil.CreateTempDir(t, "regallint_violations")
	defer cleanup()

	// opa-fmt rule: unformatted Rego triggers a violation
	policy := `package example

import rego.v1

deny[msg] {
	msg = "example violation"
}
`
	filePath := filepath.Join(tempDir, "policy.rego")
	if err := os.WriteFile(filePath, []byte(policy), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	out, err := RunRegalLint([]string{filePath})
	if err == nil {
		t.Fatalf("Expected policy with violations to fail regal lint, but it passed\nOutput: %s", out)
	}
}
