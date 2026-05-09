package main

import (
	"context"
	"fmt"
	"os"

	"pre-commit-hooks/internal/tofuscan/engine"
	"pre-commit-hooks/internal/tofuscan/output"
	"pre-commit-hooks/internal/tofuscan/policies"
	"pre-commit-hooks/internal/tofuscan/walker"
)

// Exit codes.
const (
	exitSuccess = 0 // no violations
	exitFailure = 1 // violations found
	exitError   = 3 // runtime error (I/O, policy compilation, evaluation)
)

var version = "0.1.0"

func main() {
	args := os.Args[1:]

	warnOnly := false
	paths := []string{}

	for _, arg := range args {
		if arg == "--warn-only" {
			warnOnly = true
		} else {
			paths = append(paths, arg)
		}
	}

	if len(paths) == 0 {
		paths = []string{"."}
	}

	err := RunTofuScanCLI(
		paths,
		warnOnly,
		walker.FindTofuFiles,
		func(files []string) ([]engine.Violation, error) {
			return engine.Run(context.Background(), files, policies.FS)
		},
		engine.ParseSkipDirectives,
		output.Print,
		os.Exit,
	)
	if err != nil {
		os.Exit(exitError)
	}
}

// RunTofuScanCLI runs the tofu scan CLI logic. Returns error if any step fails.
func RunTofuScanCLI(
	paths []string,
	warnOnly bool,
	findFiles func([]string) ([]string, error),
	runEngine func([]string) ([]engine.Violation, error),
	parseSkips func([]string) *engine.SkipDirectives,
	printOutput func([]engine.Violation, []engine.Violation),
	exit func(int),
) error {
	files, err := findFiles(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error finding files: %v\n", err)
		exit(exitError)
		return err
	}

	if len(files) == 0 {
		fmt.Println("No .tofu files found")
		exit(exitSuccess)
		return nil
	}

	allViolations, err := runEngine(files)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error evaluating policies: %v\n", err)
		exit(exitError)
		return err
	}

	skips := parseSkips(files)
	violations, skipped := skips.Filter(allViolations)

	printOutput(violations, skipped)

	if len(violations) > 0 && !warnOnly {
		exit(exitFailure)
	}
	return nil
}
