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

func main() {
	args := os.Args[1:]

	warnOnly := false
	paths := []string{}

	for _, arg := range args {
		switch arg {
		case "--warn-only":
			warnOnly = true
		default:
			if len(arg) > 2 && arg[:2] == "--" {
				fmt.Fprintf(os.Stderr, "unknown flag: %s\n", arg)
				os.Exit(exitError)
			}
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
		func(files []string) (*engine.RunResult, error) {
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
	runEngine func([]string) (*engine.RunResult, error),
	parseSkips func([]string) *engine.SkipDirectives,
	printOutput func([]engine.Violation, []engine.Violation, map[string]struct{}),
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

	result, err := runEngine(files)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error evaluating policies: %v\n", err)
		exit(exitError)
		return err
	}

	skips := parseSkips(files)
	violations, skipped := skips.Filter(result.Violations)

	printOutput(violations, skipped, result.ResourceTypes)

	if len(violations) > 0 && !warnOnly {
		exit(exitFailure)
	}
	return nil
}
