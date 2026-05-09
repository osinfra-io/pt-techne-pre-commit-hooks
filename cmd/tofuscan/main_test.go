package main

import (
	"fmt"
	"testing"

	"pre-commit-hooks/internal/tofuscan/engine"
)

func TestRunTofuScanCLI(t *testing.T) {
	noViolations := []engine.Violation{}
	oneViolation := []engine.Violation{{RuleID: "CIS-1.1", File: "main.tofu"}}
	noSkips := engine.ParseSkipDirectives([]string{})

	cases := []struct {
		name       string
		paths      []string
		warnOnly   bool
		files      []string
		findErr    error
		violations []engine.Violation
		engineErr  error
		wantExit   int
		wantErr    bool
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
			name:       "no violations",
			paths:      []string{"."},
			files:      []string{"main.tofu"},
			violations: noViolations,
			wantExit:   exitSuccess,
		},
		{
			name:       "violations, warn-only false",
			paths:      []string{"."},
			files:      []string{"main.tofu"},
			violations: oneViolation,
			wantExit:   exitFailure,
		},
		{
			name:       "violations, warn-only true",
			paths:      []string{"."},
			warnOnly:   true,
			files:      []string{"main.tofu"},
			violations: oneViolation,
			wantExit:   exitSuccess,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotExit int
			exitFn := func(code int) { gotExit = code }

			findFiles := func(paths []string) ([]string, error) {
				return tc.files, tc.findErr
			}
			runEngine := func(files []string) ([]engine.Violation, error) {
				return tc.violations, tc.engineErr
			}
			printOutput := func(violations []engine.Violation, skipped []engine.Violation) {}

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
