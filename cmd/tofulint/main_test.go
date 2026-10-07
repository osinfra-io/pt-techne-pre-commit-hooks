package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pre-commit-hooks/internal/testutil"
	"pre-commit-hooks/internal/tofudir"
)

func TestParseOpenTofuVersion(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantVersion string
		wantMajor   int
		wantMinor   int
		wantErr     bool
	}{
		{name: "stable version", input: "OpenTofu v1.13.1\non linux_amd64", wantVersion: "v1.13.1", wantMajor: 1, wantMinor: 13},
		{name: "major version above one", input: "OpenTofu v2.0.0", wantVersion: "v2.0.0", wantMajor: 2, wantMinor: 0},
		{name: "invalid version", input: "not a version", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, major, minor, err := parseOpenTofuVersion(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseOpenTofuVersion() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && (version != tt.wantVersion || major != tt.wantMajor || minor != tt.wantMinor) {
				t.Errorf("parseOpenTofuVersion() = (%q, %d, %d), want (%q, %d, %d)", version, major, minor, tt.wantVersion, tt.wantMajor, tt.wantMinor)
			}
		})
	}
}

func TestRunTofuLintCLI_VersionRequirement(t *testing.T) {
	called := false
	err := RunTofuLintCLI(
		nil,
		func() bool { return true },
		func() (string, error) { return "OpenTofu v1.12.2", nil },
		func() (string, error) { return "/repo", nil },
		func(string) ([]string, error) { return []string{"/repo"}, nil },
		func(string, []string) (string, error) { called = true; return "", nil },
		func(string, []string) (string, error) { called = true; return "", nil },
	)
	if err == nil {
		t.Fatal("RunTofuLintCLI() error = nil, want unsupported-version error")
	}
	if called {
		t.Error("OpenTofu commands ran before the version requirement was checked")
	}
}

func TestRunTofuLintCLI_WarningPassesAndPassesArgs(t *testing.T) {
	var lintArgs []string
	err := RunTofuLintCLI(
		[]string{"-var", "message=value", "-lint=core:no-type-variable"},
		func() bool { return true },
		func() (string, error) { return "OpenTofu v1.13.0", nil },
		func() (string, error) { return "/repo", nil },
		func(string) ([]string, error) { return []string{"/repo"}, nil },
		func(string, []string) (string, error) { return "", nil },
		func(_ string, args []string) (string, error) {
			lintArgs = args
			return "Warning: Variable with no type (core:no-type-variable)\n", nil
		},
	)
	if err != nil {
		t.Fatalf("RunTofuLintCLI() error = %v, want nil for warnings", err)
	}
	wantArgs := []string{"validate", "-no-color", "-var", "message=value", "-lint=core:no-type-variable", "-lint=all"}
	if strings.Join(lintArgs, " ") != strings.Join(wantArgs, " ") {
		t.Errorf("lint args = %v, want %v", lintArgs, wantArgs)
	}
}

func TestRunTofuLintCLI_IgnoresExperimentalNotice(t *testing.T) {
	err := RunTofuLintCLI(
		nil,
		func() bool { return true },
		func() (string, error) { return "OpenTofu v1.13.0", nil },
		func() (string, error) { return "/repo", nil },
		func(string) ([]string, error) { return []string{"/repo"}, nil },
		func(string, []string) (string, error) { return "", nil },
		func(string, []string) (string, error) {
			return "Warning: Experimental linting enabled\nThe linting functionality is under active development.", nil
		},
	)
	if err != nil {
		t.Errorf("RunTofuLintCLI() error = %v, want nil for the experimental notice alone", err)
	}
}

func TestRunTofuLintCLI_CleanWarningCards(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	oldStdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	err = RunTofuLintCLI(
		nil,
		func() bool { return true },
		func() (string, error) { return "OpenTofu v1.13.0", nil },
		func() (string, error) { return "/repo", nil },
		func(string) ([]string, error) { return []string{"/repo"}, nil },
		func(string, []string) (string, error) { return "", nil },
		func(string, []string) (string, error) {
			return `Warning: Input variable not used (core:unused-variable)
  on variables.tofu line 67:
  67: variable "state_bucket" {
Found no usage of the variable "state_bucket".
Warning: Input variable not used (core:unused-variable)
  on variables.tofu line 72:
  72: variable "state_prefix" {
Found no usage of the variable "state_prefix".
Warning: Experimental linting enabled
The linting functionality is under active development and may change or break
in future releases. You can provide feedback by opening a new issue.
Success! The configuration is valid, but there were some validation warnings
as shown above.`, nil
		},
	)
	if err != nil {
		t.Errorf("RunTofuLintCLI() error = %v, want nil for warnings", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	captured, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	got := string(captured)
	want := `╭─ [WARNING] Input variable not used
│  📄 repo/variables.tofu:67
│  🏷  core:unused-variable
│
│  Found no usage of the variable "state_bucket".
╰─

╭─ [WARNING] Input variable not used
│  📄 repo/variables.tofu:72
│  🏷  core:unused-variable
│
│  Found no usage of the variable "state_prefix".
╰─
`
	if got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestRunTofuLintCLI_ReportsVersionCommandError(t *testing.T) {
	versionErr := errors.New("version command failed")
	err := RunTofuLintCLI(
		nil,
		func() bool { return true },
		func() (string, error) { return "version output", versionErr },
		func() (string, error) { return "/repo", nil },
		func(string) ([]string, error) { return []string{"/repo"}, nil },
		func(string, []string) (string, error) { return "", nil },
		func(string, []string) (string, error) { return "", nil },
	)
	if !errors.Is(err, versionErr) {
		t.Errorf("RunTofuLintCLI() error = %v, want wrapped version error", err)
	}
}

func TestTofuLintFixtures(t *testing.T) {
	testutil.SkipIfTofuNotInstalled(t)
	versionOutput, err := getOpenTofuVersion()
	if err != nil {
		t.Fatalf("tofu version failed: %v, output: %s", err, versionOutput)
	}
	_, major, minor, err := parseOpenTofuVersion(versionOutput)
	if err != nil {
		t.Fatal(err)
	}
	if major < 1 || (major == 1 && minor < 13) {
		t.Skipf("OpenTofu v1.13 or newer is required for lint fixture tests (found %s)", versionOutput)
	}

	for _, tc := range []struct {
		name    string
		wantErr bool
	}{
		{name: "pass"},
		{name: "fail"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tempDir, cleanup := testutil.CreateTempDir(t, "tofu-lint-fixture")
			defer cleanup()
			fixturePath := filepath.Join("..", "..", "test", "tofulint", "fixtures", tc.name, "main.tofu")
			content, err := os.ReadFile(fixturePath)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(tempDir, "main.tofu"), content, 0o644); err != nil {
				t.Fatalf("copy fixture: %v", err)
			}

			err = RunTofuLintCLI(
				nil,
				testutil.CheckOpenTofuInstalled,
				getOpenTofuVersion,
				func() (string, error) { return tempDir, nil },
				tofudir.FindDirsWithTofuFiles,
				runCmdInDir,
				runTofuLint,
			)
			if (err != nil) != tc.wantErr {
				t.Errorf("RunTofuLintCLI() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestRunTofuLintCLI_InitAndLintErrors(t *testing.T) {
	t.Run("init error", func(t *testing.T) {
		initErr := errors.New("init failed")
		err := RunTofuLintCLI(
			nil,
			func() bool { return true },
			func() (string, error) { return "OpenTofu v1.13.0", nil },
			func() (string, error) { return "/repo", nil },
			func(string) ([]string, error) { return []string{"/repo"}, nil },
			func(string, []string) (string, error) { return "init output", initErr },
			func(string, []string) (string, error) { t.Error("lint command ran after init failed"); return "", nil },
		)
		if err == nil {
			t.Fatal("RunTofuLintCLI() error = nil, want init error")
		}
	})

	t.Run("lint error", func(t *testing.T) {
		lintErr := errors.New("lint command failed")
		err := RunTofuLintCLI(
			nil,
			func() bool { return true },
			func() (string, error) { return "OpenTofu v1.13.0", nil },
			func() (string, error) { return "/repo", nil },
			func(string) ([]string, error) { return []string{"/repo"}, nil },
			func(string, []string) (string, error) { return "", nil },
			func(string, []string) (string, error) {
				return "Warning: Input variable not used (core:unused-variable)\nUnused variable.\nError: Invalid configuration\nValidation failed.", lintErr
			},
		)
		if err == nil {
			t.Fatal("RunTofuLintCLI() error = nil, want lint command error")
		}
	})
}

func TestRunTofuLintCLI_DirectoryScanError(t *testing.T) {
	scanErr := errors.New("scan failed")
	err := RunTofuLintCLI(
		nil,
		func() bool { return true },
		func() (string, error) { return "OpenTofu v1.13.0", nil },
		func() (string, error) { return "/repo", nil },
		func(string) ([]string, error) { return nil, scanErr },
		func(string, []string) (string, error) { return "", nil },
		func(string, []string) (string, error) { return "", nil },
	)
	if !errors.Is(err, scanErr) {
		t.Errorf("RunTofuLintCLI() error = %v, want wrapped scan error", err)
	}
}
