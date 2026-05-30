package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"pre-commit-hooks/internal/testutil"
)

func Test_runCmdInDir(t *testing.T) {
	out, err := runCmdInDir(".", []string{"nonexistentcmd"})
	if err == nil {
		t.Error("Expected error for nonexistent command")
	}
	if out == "" {
		t.Log("Output is empty as expected for nonexistent command")
	}
}

func Test_findDirsWithTfFiles_and_walkDirs(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "finddirs_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	_ = os.Mkdir(filepath.Join(tempDir, "sub1"), 0755)
	_ = os.Mkdir(filepath.Join(tempDir, "sub2"), 0755)
	_ = os.WriteFile(filepath.Join(tempDir, "sub1", "main.tf"), []byte("terraform {}"), 0644)
	_ = os.WriteFile(filepath.Join(tempDir, "sub2", "other.txt"), []byte("not tf"), 0644)

	dirs := findDirsWithTfFiles(tempDir)
	found := false
	for _, d := range dirs {
		if strings.HasSuffix(d, "sub1") {
			found = true
		}
	}
	if !found {
		t.Error("Expected to find sub1 as a directory with .tf files")
	}
	for _, d := range dirs {
		if strings.HasSuffix(d, "sub2") {
			t.Error("Did not expect sub2 to be found as it has no .tf files")
		}
	}
}

func Test_walkDirs_ErrorsAndHidden(t *testing.T) {
	_, err := walkDirs("/nonexistent/path")
	if err == nil {
		t.Error("Expected error for non-existent directory")
	}

	tempDir, err2 := os.MkdirTemp("", "walkdirs_test")
	if err2 != nil {
		t.Fatalf("Failed to create temp dir: %v", err2)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	_ = os.Mkdir(filepath.Join(tempDir, ".hidden"), 0755)
	_ = os.Mkdir(filepath.Join(tempDir, ".terraform"), 0755)
	_ = os.Mkdir(filepath.Join(tempDir, "visible"), 0755)
	_ = os.WriteFile(filepath.Join(tempDir, "visible", "main.tf"), []byte("terraform {}"), 0644)
	_ = os.WriteFile(filepath.Join(tempDir, ".hidden", "main.tf"), []byte("terraform {}"), 0644)
	_ = os.WriteFile(filepath.Join(tempDir, ".terraform", "main.tf"), []byte("terraform {}"), 0644)

	foundDirs, err := walkDirs(tempDir)
	if err != nil {
		t.Fatalf("walkDirs failed: %v", err)
	}
	foundVisible := false
	foundHidden := false
	foundTerraform := false
	for _, d := range foundDirs {
		if strings.HasSuffix(d, "visible") {
			foundVisible = true
		}
		if strings.HasSuffix(d, ".hidden") {
			foundHidden = true
		}
		if strings.HasSuffix(d, ".terraform") {
			foundTerraform = true
		}
	}
	if !foundVisible {
		t.Error("Expected to find visible directory with .tf files")
	}
	if foundHidden {
		t.Error("Did not expect to find .hidden directory")
	}
	if foundTerraform {
		t.Error("Did not expect to find .terraform directory")
	}
}

func TestRunTofuValidateCLI_AllBranches(t *testing.T) {
	type mockArgs struct {
		checkInstalled bool
		getwdErr       error
		dirs           []string
		runCmdErr      error
		runCmdOut      string
		runValidateErr error
		runValidateOut string
	}
	cases := []struct {
		name    string
		args    mockArgs
		wantErr bool
	}{
		{"not installed", mockArgs{checkInstalled: false}, true},
		{"getwd error", mockArgs{checkInstalled: true, getwdErr: fmt.Errorf("fail")}, true},
		{"no tf dirs", mockArgs{checkInstalled: true, dirs: []string{}}, false},
		{"init error", mockArgs{checkInstalled: true, dirs: []string{"/mock"}, runCmdErr: fmt.Errorf("fail"), runCmdOut: "init fail"}, true},
		{"validate error", mockArgs{checkInstalled: true, dirs: []string{"/mock"}, runValidateErr: fmt.Errorf("fail"), runValidateOut: "validate fail"}, true},
		{"all ok", mockArgs{checkInstalled: true, dirs: []string{"/mock"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkInstalled := func() bool { return tc.args.checkInstalled }
			getwd := func() (string, error) {
				if tc.args.getwdErr != nil {
					return "", tc.args.getwdErr
				}
				return "/mockroot", nil
			}
			findDirs := func(root string) []string { return tc.args.dirs }
			runCmd := func(dir string, args []string) (string, error) {
				return tc.args.runCmdOut, tc.args.runCmdErr
			}
			runValidate := func(dir string, args []string) (string, error) {
				return tc.args.runValidateOut, tc.args.runValidateErr
			}
			err := RunTofuValidateCLI([]string{}, checkInstalled, getwd, findDirs, runCmd, runValidate)
			if tc.wantErr && err == nil {
				t.Errorf("Expected error for case %q, got nil", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Did not expect error for case %q, got: %v", tc.name, err)
			}
		})
	}

	t.Run("relPath rewriting branch", func(t *testing.T) {
		checkInstalled := func() bool { return true }
		getwd := func() (string, error) { return "/mockroot", nil }
		findDirs := func(root string) []string { return []string{"/mockroot/subdir"} }
		runCmd := func(dir string, args []string) (string, error) {
			return "init ok", nil
		}
		runValidate := func(dir string, args []string) (string, error) {
			return "validate ok", nil
		}
		err := RunTofuValidateCLI([]string{}, checkInstalled, getwd, findDirs, runCmd, runValidate)
		if err != nil {
			t.Errorf("Did not expect error for relPath rewriting branch, got: %v", err)
		}
	})

	t.Run("multi-error summary branch", func(t *testing.T) {
		checkInstalled := func() bool { return true }
		getwd := func() (string, error) { return "/mockroot", nil }
		findDirs := func(root string) []string { return []string{"/mock1", "/mock2"} }
		runCmd := func(dir string, args []string) (string, error) {
			if dir == "/mock1" {
				return "init fail", fmt.Errorf("fail")
			}
			return "init ok", nil
		}
		runValidate := func(dir string, args []string) (string, error) {
			if dir == "/mock2" {
				return "validate fail", fmt.Errorf("fail")
			}
			return "validate ok", nil
		}
		err := RunTofuValidateCLI([]string{}, checkInstalled, getwd, findDirs, runCmd, runValidate)
		if err == nil {
			t.Error("Expected error for multi-error summary branch, got nil")
		}
	})
}

// TestValidOpenTofuConfig tests that a valid config passes validation
func TestValidOpenTofuConfig(t *testing.T) {
	testutil.SkipIfTofuNotInstalled(t)
	tempDir, cleanup := testutil.CreateTempDir(t, "tofu_validate_test")
	defer cleanup()
	validDir := filepath.Join(tempDir, "valid")
	if err := os.Mkdir(validDir, 0755); err != nil {
		t.Fatalf("Failed to create valid config directory: %v", err)
	}
	validContent := `terraform {
  required_version = ">= 1.0.0"
}

resource "local_file" "example" {
  content  = "example content"
  filename = "${path.module}/example.txt"
}`
	validFilePath := filepath.Join(validDir, "main.tf")
	if err := os.WriteFile(validFilePath, []byte(validContent), 0644); err != nil {
		t.Fatalf("Failed to write valid file: %v", err)
	}
	restore := testutil.RestoreWorkingDir(t, validDir)
	defer restore()
	initCmd := exec.Command("tofu", "init")
	if initOutput, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to initialize tofu: %v, output: %s", err, initOutput)
	}
	validateCmd := exec.Command("tofu", "validate")
	if validateOutput, err := validateCmd.CombinedOutput(); err != nil {
		t.Fatalf("Expected valid config to pass validation, but it failed: %v, output: %s", err, validateOutput)
	}
}

// TestInvalidOpenTofuConfig tests that an invalid config fails validation
func TestInvalidOpenTofuConfig(t *testing.T) {
	testutil.SkipIfTofuNotInstalled(t)
	tempDir, cleanup := testutil.CreateTempDir(t, "tofu_validate_test")
	defer cleanup()
	invalidDir := filepath.Join(tempDir, "invalid")
	if err := os.Mkdir(invalidDir, 0755); err != nil {
		t.Fatalf("Failed to create invalid config directory: %v", err)
	}
	invalidContent := `terraform {
  required_version = ">= 1.0.0"
  # Missing closing brace intentionally`
	invalidFilePath := filepath.Join(invalidDir, "main.tf")
	if err := os.WriteFile(invalidFilePath, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("Failed to write invalid file: %v", err)
	}
	restore := testutil.RestoreWorkingDir(t, invalidDir)
	defer restore()
	validateCmd := exec.Command("tofu", "validate")
	output, err := validateCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("Expected invalid config to fail validation, but it passed. Output: %s", output)
	}
}

func TestHasWarning(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{
			name:   "warning at start of line",
			output: "Warning: deprecated feature\nother text",
			want:   true,
		},
		{
			name:   "box-drawing warning format",
			output: "│ Warning: something is wrong\n│ more details",
			want:   true,
		},
		{
			name:   "warning in filename should not match",
			output: "processing file warning.tf\neverything is fine",
			want:   false,
		},
		{
			name:   "warning in middle of line should not match",
			output: "this is a warning about something",
			want:   false,
		},
		{
			name:   "no warning",
			output: "success\nvalidation passed",
			want:   false,
		},
		{
			name:   "case insensitive warning",
			output: "WARNING: This is a problem",
			want:   true,
		},
		{
			name:   "warning with leading whitespace",
			output: "  Warning: indented warning",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasWarning(tt.output)
			if got != tt.want {
				t.Errorf("hasWarning() = %v, want %v for output:\n%s", got, tt.want, tt.output)
			}
		})
	}
}
