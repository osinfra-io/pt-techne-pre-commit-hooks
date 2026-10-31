package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pre-commit-hooks/internal/testutil"
	"pre-commit-hooks/internal/tofudir"
)

func TestSharedDeclarationsAndTestInputs(t *testing.T) {
	testutil.SkipIfTofuNotInstalled(t)
	root := t.TempDir()
	t.Chdir(root)
	files := map[string]string{
		"shared/locals.tofu": `locals {
  shared = "used by production"
  dead   = "unused everywhere"
}`,
		"production/main.tofu": `output "shared" { value = local.shared }`,
		"unrelated/main.tofu": `locals { dead = "different declaration" }
output "dead" { value = local.dead }`,
		"fixture/variables.tofu": `variable "previous" { type = string }
variable "unused" { type = string }`,
		"production/tests/check.tftest.hcl": `run "fixture" {
  command = plan
  module { source = "../fixture" }
  variables { previous = "before" }
  assert {
    condition = var.previous == "before"
    error_message = "Previous state must be available to assertions."
  }
}`,
	}
	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{"production", "fixture"} {
		if err := os.Symlink("../shared/locals.tofu", filepath.Join(dir, "locals.tofu")); err != nil {
			t.Fatal(err)
		}
	}
	dirs, err := tofudir.FindDirsWithTofuFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	used, err := referencedDeclarations(dirs)
	if err != nil {
		t.Fatal(err)
	}
	if !used[declaration{filepath.Join(root, "shared/locals.tofu"), "local", "shared"}] {
		t.Error("shared local usage was not associated with its canonical file")
	}
	if used[declaration{filepath.Join(root, "shared/locals.tofu"), "local", "dead"}] {
		t.Error("an unrelated declaration with the same name hid an unused local")
	}
	runner := newLintRunner()
	for _, dir := range []string{"shared", "fixture"} {
		out, err := runner(filepath.Join(root, dir), []string{"validate", "-lint=all"})
		if err != nil {
			t.Fatalf("lint %s: %v\n%s", dir, err, out)
		}
		if strings.Contains(out, `local value "shared"`) || strings.Contains(out, `variable "previous"`) {
			t.Errorf("lint %s reported a referenced shared/test declaration:\n%s", dir, out)
		}
		if !strings.Contains(out, `local value "dead"`) {
			t.Errorf("lint %s dropped a genuinely unused local:\n%s", dir, out)
		}
		if dir == "fixture" && !strings.Contains(out, `variable "unused"`) {
			t.Errorf("lint dropped a genuinely unused fixture input:\n%s", out)
		}
	}
}

func TestSharedLintPreservesValidationErrors(t *testing.T) {
	testutil.SkipIfTofuNotInstalled(t)
	root := t.TempDir()
	t.Chdir(root)
	if err := os.WriteFile("main.tofu", []byte(`output "invalid" { value = local.missing }`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := newLintRunner()(root, []string{"validate", "-lint=all"})
	if err == nil || !strings.Contains(out, "Reference to undeclared local value") {
		t.Fatalf("validation error was lost: %v\n%s", err, out)
	}
}
