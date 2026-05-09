package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"pre-commit-hooks/internal/output"
	tofufmt "pre-commit-hooks/internal/tofufmt"
)

func main() {
	err := RunTofuFmtCLI(
		os.Args[1:],
		os.Getwd,
		tofufmt.RunTofuFmt,
		tofufmt.FormatFiles,
	)
	if err != nil {
		os.Exit(1)
	}
}

// RunTofuFmtCLI runs the tofu fmt CLI logic. Returns error if any step fails.
func RunTofuFmtCLI(
	extraArgs []string,
	getwd func() (string, error),
	runTofuFmt func(string, []string) (string, error),
	formatFiles func(string, []string) error,
) error {
	if !tofufmt.CheckOpenTofuInstalled() {
		fmt.Println("OpenTofu is not installed or not in PATH.")
		return fmt.Errorf("OpenTofu not installed")
	}
	wd, err := getwd()
	if err != nil {
		fmt.Println("Error getting current directory:", err)
		return err
	}
	baseDir := filepath.Base(wd)
	printStatus(output.Running, fmt.Sprintf("Running tofu fmt recursively in: %s", baseDir))

	outputStr, err := runTofuFmt(wd, extraArgs)
	fmt.Println()
	if err != nil {
		c := output.NewCard(output.Yellow)
		c.Open(output.Badge("WARNING", output.BoldYellow), output.Title("Unformatted OpenTofu files"))
		c.Line(fmt.Sprintf("%s %s", output.File, output.Colorize(baseDir, output.Gray)))
		c.Blank()
		for _, line := range strings.Split(outputStr, "\n") {
			if strings.TrimSpace(line) != "" {
				c.Line(fmt.Sprintf("%s%s%s", output.Dim, line, output.Reset))
			}
		}
		c.Close()
		fmt.Println()
		printStatus(output.Running, "Formatting files with tofu fmt...")
		fmtErr := formatFiles(wd, extraArgs)
		fmt.Println()
		if fmtErr != nil {
			ec := output.NewCard(output.Red)
			ec.Open(output.Badge("ERROR", output.BoldRed), output.Title("tofu fmt failed"))
			ec.Line(fmt.Sprintf("%s %s", output.File, output.Colorize(baseDir, output.Gray)))
			ec.Blank()
			ec.Line(fmt.Sprintf("%s%s%s", output.Dim, fmtErr.Error(), output.Reset))
			ec.Close()
			return fmtErr
		}
		printStatus(output.ThumbsUp, "Files formatted successfully with tofu fmt.")
		fmt.Println()
	} else {
		printStatus(output.ThumbsUp, "All OpenTofu files are formatted.")
		fmt.Println()
	}
	return nil
}

// printStatus prints a colored emoji status message
func printStatus(emoji, msg string) {
	fmt.Println(output.EmojiColorText(emoji, msg, output.Green))
}
