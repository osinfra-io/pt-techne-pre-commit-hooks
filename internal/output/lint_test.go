package output

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestParseLintFindings(t *testing.T) {
	raw := `╷
│ Warning: Input variable not used (core:unused-variable)
│
│   on variables.tofu line 67:
│   67: variable "state_bucket" {
│
│ Found no usage of the variable "state_bucket".
╵
Warning: Experimental linting enabled
The linting functionality is under active development.
Warning: A warning without a rule
Additional details
on a second line.
Error: Invalid configuration
Do not include this error in the warning card.
Success! The configuration is valid, but there were some validation warnings
as shown above.`
	want := []lintFinding{
		{
			title:       "Input variable not used",
			rule:        "core:unused-variable",
			location:    "variables.tofu:67",
			description: []string{`Found no usage of the variable "state_bucket".`},
		},
		{
			title:       "A warning without a rule",
			description: []string{"Additional details", "on a second line."},
		},
	}

	if got := parseLintFindings(raw); !reflect.DeepEqual(got, want) {
		t.Errorf("parseLintFindings() = %#v, want %#v", got, want)
	}
}

func TestPrintLintWarningSummary_PreservesLocations(t *testing.T) {
	raw := func(file string, line int) string {
		return fmt.Sprintf("╷\n│ Warning: Input variable not used (core:unused-variable)\n│\n│   on %s line %d:\n│   %d: variable \"project\" {\n│\n│ Found no usage of the variable \"project\".\n╵", file, line, line)
	}
	messages := []TofuMessage{
		{Step: "lint", RelPath: "repo/a", Output: raw("variables.tofu", 16)},
		{Step: "lint", RelPath: "repo/b", Output: raw("inputs.tofu", 42)},
		{Step: "lint", RelPath: "repo/c", Output: raw("variables.tofu", 16)},
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	oldStdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()
	PrintLintWarningSummary(messages)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	captured, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	got := string(captured)
	for _, location := range []string{"repo/a/variables.tofu:16", "repo/b/inputs.tofu:42", "repo/c/variables.tofu:16"} {
		if !strings.Contains(got, location) {
			t.Errorf("output missing %q:\n%s", location, got)
		}
	}
	if strings.Contains(got, "repo/b/variables.tofu:16") {
		t.Errorf("output reused another directory's location:\n%s", got)
	}
	if count := strings.Count(got, Badge("WARNING", BoldYellow)); count != 2 {
		t.Errorf("got %d warning cards, want 2 with identical diagnostics grouped:\n%s", count, got)
	}
}
