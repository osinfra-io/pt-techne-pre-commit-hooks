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
