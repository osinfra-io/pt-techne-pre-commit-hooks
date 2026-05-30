package output

import (
	"fmt"
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
	_ = w.Close()
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
	_ = w.Close()
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
	// Simulate the same error seen from 3 directories with different path styles.
	errBlock := func(path string) string {
		return fmt.Sprintf("╷\n│ Error: Unsupported block type\n│\n│   on %s line 18, in resource \"google_container_cluster\" \"this\":\n│   18:   lifZecycle {\n│\n│ Blocks of type \"lifZecycle\" are not expected here.\n╵", path)
	}
	msgs := []TofuMessage{
		{Step: "validate", RelPath: "project/regional", Output: errBlock("main.tofu")},
		{Step: "validate", RelPath: "project/tests/fixtures/a", Output: errBlock("../../../../regional/main.tofu")},
		{Step: "validate", RelPath: "project/tests/fixtures/b", Output: errBlock("../../../../regional/main.tofu")},
		// Root dir often contains the same error block twice.
		{Step: "validate", RelPath: "project", Output: errBlock("regional/main.tofu") + "\n" + errBlock("regional/main.tofu")},
	}

	groups := groupMessages(msgs)

	if len(groups) != 1 {
		t.Errorf("Expected 1 group after dedup, got %d", len(groups))
		for i, g := range groups {
			t.Logf("  group %d: paths=%v", i, g.paths)
		}
	}
	if len(groups) > 0 && len(groups[0].paths) != 4 {
		t.Errorf("Expected 4 paths in group, got %d: %v", len(groups[0].paths), groups[0].paths)
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
