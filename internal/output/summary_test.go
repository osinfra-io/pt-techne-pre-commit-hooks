package output

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestPrintWarningSummary(t *testing.T) {
	msgs := []TofuMessage{
		{Step: "init", RelPath: "dir1", Output: "Warning: something happened\nDetails here"},
		{Step: "validate", RelPath: "dir2", Output: "Warning: another warning\nMore details"},
	}
	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	PrintWarningSummary(msgs)
	w.Close()
	outBytes, _ := io.ReadAll(r)
	output := string(outBytes)
	if !strings.Contains(output, "WARNING") {
		t.Errorf("Expected WARNING badge, got: %s", output)
	}
	if !strings.Contains(output, "╭─") || !strings.Contains(output, "╰─") {
		t.Error("Expected card border characters in output")
	}
	if !strings.Contains(output, "OpenTofu init") || !strings.Contains(output, "OpenTofu validate") {
		t.Errorf("Expected step names in card titles, got: %s", output)
	}
	if !strings.Contains(output, "dir1") || !strings.Contains(output, "dir2") {
		t.Errorf("Expected directory paths in output, got: %s", output)
	}
}

func TestPrintErrorSummary(t *testing.T) {
	msgs := []TofuMessage{
		{Step: "validate", RelPath: "dir3", Output: "Error: failed validation\nDetails"},
	}
	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	PrintErrorSummary(msgs)
	w.Close()
	outBytes, _ := io.ReadAll(r)
	output := string(outBytes)
	if !strings.Contains(output, "ERROR") {
		t.Errorf("Expected ERROR badge, got: %s", output)
	}
	if !strings.Contains(output, "╭─") || !strings.Contains(output, "╰─") {
		t.Error("Expected card border characters in output")
	}
	if !strings.Contains(output, "validate failed") {
		t.Errorf("Expected 'validate failed' in card title, got: %s", output)
	}
	if !strings.Contains(output, "dir3") {
		t.Errorf("Expected directory path in output, got: %s", output)
	}
}

func TestGroupMessages_Dedup(t *testing.T) {
	msgs := []TofuMessage{
		{Step: "validate", RelPath: "project/regional", Output: "Error on main.tofu line 18"},
		{Step: "validate", RelPath: "project/tests/fixtures/a", Output: "Error on ../../../../regional/main.tofu line 18"},
		{Step: "validate", RelPath: "project/tests/fixtures/b", Output: "Error on ../../../../regional/main.tofu line 18"},
	}

	groups := groupMessages(msgs)

	// The first message differs (main.tofu vs regional/main.tofu), but
	// messages 2 and 3 normalize to the same output and should be grouped.
	if len(groups) > 2 {
		t.Errorf("Expected at most 2 groups after dedup, got %d", len(groups))
	}

	// Find the group with multiple paths.
	var multiPath *errorGroup
	for _, g := range groups {
		if len(g.paths) > 1 {
			multiPath = g
		}
	}
	if multiPath == nil {
		t.Fatal("Expected at least one group with multiple paths")
	}
	if len(multiPath.paths) != 2 {
		t.Errorf("Expected 2 paths in deduped group, got %d", len(multiPath.paths))
	}
}

func TestGroupMessages_DifferentSteps(t *testing.T) {
	msgs := []TofuMessage{
		{Step: "init", RelPath: "dir1", Output: "same output"},
		{Step: "validate", RelPath: "dir1", Output: "same output"},
	}

	groups := groupMessages(msgs)
	if len(groups) != 2 {
		t.Errorf("Expected 2 groups for different steps, got %d", len(groups))
	}
}
