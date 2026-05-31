package main

import (
	"fmt"
	"os"
	"strings"

	"pre-commit-hooks/internal/regallint"
)

func main() {
	err := RunRegalLintCLI(
		os.Args[1:],
		regallint.CheckRegalInstalled,
		regallint.RunRegalLint,
	)
	if err != nil {
		os.Exit(1)
	}
}

// RunRegalLintCLI runs the regal lint CLI logic. Returns error if any step fails.
func RunRegalLintCLI(
	args []string,
	checkInstalled func() bool,
	runLint func([]string) (string, error),
) error {
	if !checkInstalled() {
		fmt.Println("Regal is not installed or not in PATH.")
		return fmt.Errorf("regal not installed")
	}

	hasFiles := false
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			hasFiles = true
			break
		}
	}

	if !hasFiles {
		fmt.Println("No Rego files to lint.")
		return nil
	}

	out, err := runLint(args)
	if out != "" {
		fmt.Print(out)
	}
	return err
}
