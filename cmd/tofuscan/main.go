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
	exitUsage   = 2 // invalid arguments
	exitError   = 3 // runtime error (I/O, policy compilation, evaluation)
)

var version = "0.1.0"

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "tofuscan %s\nUsage: tofuscan <path...>\n", version)
		os.Exit(exitUsage)
	}

	files, err := walker.FindTofuFiles(args)
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

	output.Print(violations, len(skipped))

	if len(violations) > 0 {
		os.Exit(exitFailure)
	}
}
