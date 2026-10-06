package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"pre-commit-hooks/internal/output"
	"pre-commit-hooks/internal/testutil"
	"pre-commit-hooks/internal/tofudir"
)

func main() {
	err := RunTofuLintCLI(
		os.Args[1:],
		testutil.CheckOpenTofuInstalled,
		getOpenTofuVersion,
		os.Getwd,
		tofudir.FindDirsWithTofuFiles,
		runCmdInDir,
		runTofuLint,
	)
	if err != nil {
		os.Exit(1)
	}
}

// RunTofuLintCLI runs OpenTofu lint checks in each directory containing configuration.
func RunTofuLintCLI(
	extraArgs []string,
	checkInstalled func() bool,
	getVersion func() (string, error),
	getwd func() (string, error),
	findDirs func(string) ([]string, error),
	runCmd func(string, []string) (string, error),
	runLint func(string, []string) (string, error),
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

	dirsWithTofu, err := findDirs(rootDir)
	if err != nil {
		fmt.Printf("Error scanning directories: %v\n", err)
		return err
	}
	if len(dirsWithTofu) == 0 {
		fmt.Println("No directories with OpenTofu files found.")
		return nil
	}

	versionOutput, err := getVersion()
	if err != nil {
		fmt.Printf("Could not determine OpenTofu version: %v\n", err)
		if strings.TrimSpace(versionOutput) != "" {
			fmt.Println(strings.TrimSpace(versionOutput))
		}
		return fmt.Errorf("could not determine OpenTofu version: %w", err)
	}
	version, major, minor, err := parseOpenTofuVersion(versionOutput)
	if err != nil {
		fmt.Println(err)
		return err
	}
	if major < 1 || (major == 1 && minor < 13) {
		fmt.Printf("tofu-lint requires OpenTofu v1.13 or newer (found %s).\n", version)
		return fmt.Errorf("unsupported OpenTofu version %s", version)
	}

	var errorMessages []output.TofuMessage
	var warningMessages []output.TofuMessage
	baseDir := filepath.Base(rootDir)
	for _, dir := range dirsWithTofu {
		relPath, err := filepath.Rel(rootDir, dir)
		if err != nil {
			relPath = dir
		}
		fullPath := baseDir
		if relPath != "." {
			if strings.HasPrefix(relPath, "..") {
				fullPath = filepath.Base(dir)
			} else {
				fullPath += "/" + relPath
			}
		}

		out, err := runCmd(dir, []string{"init", "-input=false", "--backend=false"})
		if err != nil {
			errorMessages = append(errorMessages, output.TofuMessage{Step: "lint init", RelPath: fullPath, Output: out})
			continue
		}

		lintArgs := append([]string{"validate", "-no-color"}, extraArgs...)
		lintArgs = append(lintArgs, "-lint=all")
		out, err = runLint(dir, lintArgs)
		if output.HasLintWarning(out) {
			warningMessages = append(warningMessages, output.TofuMessage{Step: "lint", RelPath: fullPath, Output: out})
		}
		if err != nil {
			errorMessages = append(errorMessages, output.TofuMessage{Step: "lint", RelPath: fullPath, Output: out})
		}
	}

	if len(warningMessages) > 0 {
		output.PrintWarningSummary(warningMessages)
	}
	if len(errorMessages) > 0 {
		output.PrintErrorSummary(errorMessages)
		return fmt.Errorf("lint failed")
	}
	if len(warningMessages) > 0 {
		return fmt.Errorf("lint warnings found")
	}
	return nil
}

func parseOpenTofuVersion(versionOutput string) (string, int, int, error) {
	for _, field := range strings.Fields(versionOutput) {
		version := strings.TrimPrefix(field, "v")
		parts := strings.Split(version, ".")
		if len(parts) < 2 {
			continue
		}
		major, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		minorPart := strings.SplitN(parts[1], "-", 2)[0]
		minor, err := strconv.Atoi(minorPart)
		if err != nil {
			continue
		}
		return field, major, minor, nil
	}
	return "", 0, 0, fmt.Errorf("could not parse OpenTofu version from: %s", strings.TrimSpace(versionOutput))
}

func getOpenTofuVersion() (string, error) {
	cmd := exec.Command("tofu", "version")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func runTofuLint(dir string, args []string) (string, error) {
	cmd := exec.Command("tofu", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func runCmdInDir(dir string, args []string) (string, error) {
	cmd := exec.Command("tofu", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}
