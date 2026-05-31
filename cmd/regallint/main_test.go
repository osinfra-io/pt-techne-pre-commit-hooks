package main

import (
	"fmt"
	"testing"
)

func TestRunRegalLintCLI_NotInstalled(t *testing.T) {
	checkInstalled := func() bool { return false }
	runLint := func(args []string) (string, error) { return "", nil }

	err := RunRegalLintCLI([]string{"policy.rego"}, checkInstalled, runLint)
	if err == nil {
		t.Error("Expected error when regal is not installed, got nil")
	}
}

func TestRunRegalLintCLI_NoFiles(t *testing.T) {
	checkInstalled := func() bool { return true }
	runLint := func(args []string) (string, error) { return "", nil }

	err := RunRegalLintCLI([]string{}, checkInstalled, runLint)
	if err != nil {
		t.Errorf("Expected nil when no files provided, got: %v", err)
	}
}

func TestRunRegalLintCLI_OnlyFlags(t *testing.T) {
	checkInstalled := func() bool { return true }
	runLint := func(args []string) (string, error) { return "", nil }

	err := RunRegalLintCLI([]string{"--fail-level", "warning"}, checkInstalled, runLint)
	if err != nil {
		t.Errorf("Expected nil when only flags provided (no files), got: %v", err)
	}
}

func TestRunRegalLintCLI_LintError(t *testing.T) {
	checkInstalled := func() bool { return true }
	runLint := func(args []string) (string, error) {
		return "violations found\n", fmt.Errorf("exit status 1")
	}

	err := RunRegalLintCLI([]string{"policy.rego"}, checkInstalled, runLint)
	if err == nil {
		t.Error("Expected error when regal reports violations, got nil")
	}
}

func TestRunRegalLintCLI_AllOk(t *testing.T) {
	checkInstalled := func() bool { return true }
	runLint := func(args []string) (string, error) { return "", nil }

	err := RunRegalLintCLI([]string{"policy.rego"}, checkInstalled, runLint)
	if err != nil {
		t.Errorf("Expected nil when no violations, got: %v", err)
	}
}

func TestRunRegalLintCLI_ExtraFlagsAndFiles(t *testing.T) {
	checkInstalled := func() bool { return true }

	var capturedArgs []string
	runLint := func(args []string) (string, error) {
		capturedArgs = args
		return "", nil
	}

	err := RunRegalLintCLI([]string{"--fail-level", "warning", "policy.rego"}, checkInstalled, runLint)
	if err != nil {
		t.Errorf("Expected nil, got: %v", err)
	}
	if len(capturedArgs) != 3 {
		t.Errorf("Expected 3 args passed to runLint, got %d: %v", len(capturedArgs), capturedArgs)
	}
}
