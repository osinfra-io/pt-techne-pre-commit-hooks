package main

import (
	"fmt"
	"testing"

	"pre-commit-hooks/internal/tofuscan/engine"
)

func TestRunTofuScanCLI(t *testing.T) {
	noViolations := &engine.RunResult{Violations: []engine.Violation{}}
	oneViolation := &engine.RunResult{Violations: []engine.Violation{{RuleID: "CIS-1.1", File: "main.tofu"}}}
	noSkips := engine.ParseSkipDirectives([]string{})

	cases := []struct {
		name      string
		paths     []string
		warnOnly  bool
		files     []string
		findErr   error
		result    *engine.RunResult
		engineErr error
		wantExit  int
		wantErr   bool
	}{
		{
			name:     "no files found",
			paths:    []string{"."},
			files:    []string{},
			wantExit: exitSuccess,
		},
		{
			name:     "find files error",
			paths:    []string{"."},
			findErr:  fmt.Errorf("walk error"),
			wantExit: exitError,
			wantErr:  true,
		},
		{
			name:      "engine error",
			paths:     []string{"."},
			files:     []string{"main.tofu"},
			engineErr: fmt.Errorf("opa error"),
			wantExit:  exitError,
			wantErr:   true,
		},
		{
			name:     "no violations",
			paths:    []string{"."},
			files:    []string{"main.tofu"},
			result:   noViolations,
			wantExit: exitSuccess,
		},
		{
			name:     "violations, warn-only false",
			paths:    []string{"."},
			files:    []string{"main.tofu"},
			result:   oneViolation,
			wantExit: exitFailure,
		},
		{
			name:     "violations, warn-only true",
			paths:    []string{"."},
			warnOnly: true,
			files:    []string{"main.tofu"},
			result:   oneViolation,
			wantExit: exitSuccess,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotExit int
			exitFn := func(code int) { gotExit = code }

			findFiles := func(paths []string) ([]string, error) {
				return tc.files, tc.findErr
			}
			runEngine := func(files []string) (*engine.RunResult, error) {
				return tc.result, tc.engineErr
			}
			printOutput := func(violations []engine.Violation, skipped []engine.Violation, resourceTypes map[string]struct{}) {
			}

			err := RunTofuScanCLI(
				tc.paths,
				tc.warnOnly,
				findFiles,
				runEngine,
				func(files []string) *engine.SkipDirectives { return noSkips },
				printOutput,
				exitFn,
			)

			if tc.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if gotExit != tc.wantExit {
				t.Errorf("exit code = %d, want %d", gotExit, tc.wantExit)
			}
		})
	}
}
