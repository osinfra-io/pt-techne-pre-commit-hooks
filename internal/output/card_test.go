package output

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestCard(t *testing.T) {
	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	c := NewCard(Red)
	c.Open(Badge("ERROR", BoldRed), Title("Something failed"))
	c.Line(File + " test.tofu:42")
	c.Blank()
	c.Line(Dim + "description line" + Reset)
	c.Close()

	w.Close()
	outBytes, _ := io.ReadAll(r)
	out := string(outBytes)

	if !strings.Contains(out, "╭─") {
		t.Error("Expected card open border")
	}
	if !strings.Contains(out, "╰─") {
		t.Error("Expected card close border")
	}
	if !strings.Contains(out, "[ERROR]") {
		t.Error("Expected ERROR badge")
	}
	if !strings.Contains(out, "Something failed") {
		t.Error("Expected title text")
	}
	if !strings.Contains(out, "test.tofu:42") {
		t.Error("Expected file reference line")
	}
	if !strings.Contains(out, "description line") {
		t.Error("Expected description line")
	}
}

func TestBadge(t *testing.T) {
	b := Badge("HIGH", BoldRed)
	if !strings.Contains(b, "[HIGH]") {
		t.Errorf("Badge() = %q, expected [HIGH]", b)
	}
}

func TestTitle_Output(t *testing.T) {
	tt := Title("My Title")
	if !strings.Contains(tt, "My Title") {
		t.Errorf("Title() = %q, expected My Title", tt)
	}
}

func TestWrapText(t *testing.T) {
	text := "This is a long sentence that should be wrapped at the word boundary"
	lines := WrapText(text, 30)
	for _, line := range lines {
		if len(line) > 30 {
			t.Errorf("Line exceeds width: %q (%d chars)", line, len(line))
		}
	}
	joined := strings.Join(lines, " ")
	if joined != text {
		t.Errorf("WrapText lost content: got %q, want %q", joined, text)
	}
}
