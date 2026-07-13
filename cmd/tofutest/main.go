package main

import (
	"fmt"
	"os"
	"strings"

	"pre-commit-hooks/internal/output"
	"pre-commit-hooks/internal/testutil"
	"pre-commit-hooks/internal/tofutest"
)

func main() {
	err := RunTofuTestCLI(
		parseExtraArgs(os.Args[1:]),
		testutil.CheckOpenTofuInstalled,
		os.Getwd,
		tofutest.HasTestFiles,
		tofutest.RunTofuTest,
		printStatus,
	)
	if err != nil {
		os.Exit(1)
	}
}

// RunTofuTestCLI runs the tofu test CLI logic. Returns error if any step fails.
func RunTofuTestCLI(
	extraArgs []string,
	checkInstalled func() bool,
	getwd func() (string, error),
	hasTestFiles func(string) (bool, error),
	runTest func(string, []string) (string, error),
	printStatus func(string, string),
) error {
	if !checkInstalled() {
		fmt.Println("OpenTofu is not installed or not in PATH.")
		return fmt.Errorf("OpenTofu not installed")
	}

	rootDir, err := getwd()
	if err != nil {
		fmt.Println("Could not get working directory.")
		return err
	}

	hasTests, err := hasTestFiles(rootDir)
	if err != nil {
		fmt.Printf("Error checking for test files: %v\n", err)
		return err
	}

	if !hasTests {
		printStatus(output.Running, "No OpenTofu test files (.tftest.hcl) found, skipping tests.")
		return nil
	}

	testOutput, err := runTest(rootDir, extraArgs)

	if err != nil {
		fmt.Println()
		c := output.NewCard(output.Red)
		c.Open(output.Badge("FAIL", output.BoldRed), output.Title("OpenTofu test"))
		c.Blank()
		for _, line := range strings.Split(testOutput, "\n") {
			if strings.TrimSpace(line) != "" {
				c.Line(fmt.Sprintf("%s%s%s", output.Dim, line, output.Reset))
			}
		}
		c.Close()
		fmt.Println()
		printStatus(output.Error, "OpenTofu test failed.")
		fmt.Println()
		return fmt.Errorf("test failed: %w", err)
	}

	c := output.NewCard(output.Green)
	c.Open(output.Badge("PASS", output.BoldGreen), output.Title("OpenTofu test"))
	c.Blank()
	for _, line := range strings.Split(testOutput, "\n") {
		if strings.TrimSpace(line) != "" {
			c.Line(fmt.Sprintf("%s%s%s", output.Dim, line, output.Reset))
		}
	}
	c.Close()
	fmt.Println()
	return nil
}

// printStatus prints a colored emoji status message
func printStatus(emoji, msg string) {
	fmt.Println(output.EmojiColorText(emoji, msg, output.Green))
}

// parseExtraArgs filters os.Args tokens, keeping only flags (tokens starting
// with '-') and their values. Equals-form flags (-flag=value) are kept as a
// single token. Split-form flags (-flag value) are kept as two tokens, but
// only for flags known to accept a value argument — boolean flags will not
// accidentally consume the next token. A "--" token ends flag processing.
func parseExtraArgs(args []string) []string {
	// knownValueFlags lists tofu test flags that accept a value in split form.
	knownValueFlags := map[string]bool{
		"-filter":         true,
		"-test-directory": true,
		"-var":            true,
		"-var-file":       true,
	}

	extraArgs := []string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		if strings.HasPrefix(arg, "-") {
			extraArgs = append(extraArgs, arg)
			// Only consume the next token as a value for flags known to accept
			// one, and only when no value is already embedded via '='.
			if !strings.Contains(arg, "=") && knownValueFlags[arg] &&
				i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				extraArgs = append(extraArgs, args[i+1])
				i++ // skip the value token
			}
		}
	}
	return extraArgs
}
