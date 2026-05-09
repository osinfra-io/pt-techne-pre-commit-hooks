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

	softFail := false
	paths := []string{}

	for _, arg := range args {
		if arg == "--soft-fail" {
			softFail = true
		} else {
			paths = append(paths, arg)
		}
	}

	if len(paths) == 0 {
		paths = []string{"."}
	}

	files, err := walker.FindTofuFiles(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error finding files: %v\n", err)
		os.Exit(exitError)
	}

	if len(files) == 0 {
		fmt.Println("No .tofu files found")
		return
	}

	allViolations, err := engine.Run(context.Background(), files, policies.FS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error evaluating policies: %v\n", err)
		os.Exit(exitError)
	}

	skips := engine.ParseSkipDirectives(files)
	violations, skipped := skips.Filter(allViolations)

	output.Print(violations, skipped)

	if len(violations) > 0 && !softFail {
		os.Exit(exitFailure)
	}
}
