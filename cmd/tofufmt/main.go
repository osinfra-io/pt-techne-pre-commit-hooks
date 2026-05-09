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
	outputStr, err := runTofuFmt(wd, extraArgs)
	fmt.Println()
	if err != nil {
		c := output.NewCard(output.Yellow)
		c.Open(output.Badge("WARNING", output.BoldYellow), output.Title("Unformatted OpenTofu files"))
		c.Line(fmt.Sprintf("%s %s", output.File, output.Colorize(baseDir, output.Gray)))
		c.Blank()
		for _, line := range strings.Split(outputStr, "\n") {
			if strings.TrimSpace(line) != "" {
				var color string
				switch {
				case strings.HasPrefix(line, "+"):
					color = output.Green
				case strings.HasPrefix(line, "-"):
					color = output.Yellow
				default:
					color = output.Dim
				}
				c.Line(fmt.Sprintf("%s%s%s", color, line, output.Reset))
			}
		}
		c.Close()
		fmt.Println()
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
	}
	return nil
}
