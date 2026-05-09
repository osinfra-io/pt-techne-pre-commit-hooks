package output

import (
	"fmt"
	"strings"
)

// TofuMessage holds the result of a tofu command step.
type TofuMessage struct {
	Step    string
	RelPath string
	Output  string
}

// PrintWarningSummary prints warning messages as styled cards.
func PrintWarningSummary(warningMessages []TofuMessage) {
	if len(warningMessages) == 0 {
		return
	}
	for i, msg := range warningMessages {
		c := NewCard(Yellow)
		c.Open(Badge("WARNING", BoldYellow), Title("OpenTofu "+msg.Step))
		c.Line(fmt.Sprintf("%s %s", File, Colorize(msg.RelPath, Gray)))
		c.Blank()

		lines := strings.Split(msg.Output, "\n")
		inWarning := false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.Contains(trimmed, "Warning:") {
				inWarning = true
			}
			if inWarning && trimmed != "" {
				c.Line(fmt.Sprintf("%s%s%s", Dim, line, Reset))
			}
		}
		c.Close()
		if i < len(warningMessages)-1 {
			fmt.Println()
		}
	}
}

// PrintErrorSummary prints error messages as styled cards.
func PrintErrorSummary(errorMessages []TofuMessage) {
	if len(errorMessages) == 0 {
		return
	}
	for i, msg := range errorMessages {
		c := NewCard(Red)
		c.Open(Badge("ERROR", BoldRed), Title("OpenTofu "+msg.Step+" failed"))
		c.Line(fmt.Sprintf("%s %s", File, Colorize(msg.RelPath, Gray)))
		c.Blank()

		lines := strings.Split(msg.Output, "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				c.Line(fmt.Sprintf("%s%s%s", Dim, line, Reset))
			}
		}
		c.Close()
		if i < len(errorMessages)-1 {
			fmt.Println()
		}
	}
}
