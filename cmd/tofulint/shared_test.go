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
variable "unused" { type = string }
variable "token" { type = string }`,
		"production/tests/check.tftest.hcl": `variables { token = "test-file value" }
run "fixture" {
  command = plan
  module { source = "../fixture-alias" }
  variables {
    previous = "before"
    token = var.token
  }
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
	if err := os.Symlink("fixture", filepath.Join(root, "fixture-alias")); err != nil {
		t.Fatal(err)
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
		if dir == "fixture" && !strings.Contains(out, `variable "token"`) {
			t.Errorf("test-file input forwarding hid an unused fixture input:\n%s", out)
		}
	}

}

func TestSharedLintIndexFailureDoesNotBlockValidation(t *testing.T) {
	testutil.SkipIfTofuNotInstalled(t)
	for _, failure := range []string{"syntax error", "broken symlink"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			t.Chdir(root)
			if err := os.Mkdir("broken", 0o755); err != nil {
				t.Fatal(err)
			}
			if failure == "syntax error" {
				if err := os.WriteFile("broken/main.tofu", []byte("locals {"), 0o644); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Symlink("missing.tofu", "broken/main.tofu"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile("main.tofu", []byte(`locals { unused = true }`), 0o644); err != nil {
				t.Fatal(err)
			}
			runner := newLintRunner()
			out, err := runner(root, []string{"validate", "-lint=all"})
			if err != nil || !strings.Contains(out, `local value "unused"`) {
				t.Fatalf("independent lint warning was lost: %v\n%s", err, out)
			}
			if err := os.WriteFile("main.tofu", []byte(`output "invalid" { value = local.missing }`), 0o644); err != nil {
				t.Fatal(err)
			}
			out, err = runner(root, []string{"validate", "-lint=all"})
			if err == nil || !strings.Contains(out, "Reference to undeclared local value") {
				t.Fatalf("independent validation error was lost: %v\n%s", err, out)
			}
		})
	}
}

func TestSharedLintIgnoresInactiveConfigurationFiles(t *testing.T) {
	testutil.SkipIfTofuNotInstalled(t)
	root := t.TempDir()
	t.Chdir(root)
	files := map[string]string{
		"main.tofu": `locals {
	  unused = true
	  shadowed = true
	}`,
		"output.tofu":  `output "active" { value = true }`,
		"output.tf":    `output "ignored" { value = local.shadowed }`,
		".hidden.tofu": `output "ignored" { value = local.unused }`,
		".invalid.tf":  `locals {`,
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out, err := newLintRunner()(root, []string{"validate", "-lint=all"})
	if err != nil {
		t.Fatalf("ignored file prevented linting: %v\n%s", err, out)
	}
	for _, name := range []string{"unused", "shadowed"} {
		if !strings.Contains(out, `local value "`+name+`"`) {
			t.Errorf("inactive file hid unused local %s:\n%s", name, out)
		}
	}
	if err := os.WriteFile("output.tf", []byte("locals {"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := referencedDeclarations([]string{root}); err != nil {
		t.Fatalf("overridden .tf syntax error prevented indexing: %v", err)
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
