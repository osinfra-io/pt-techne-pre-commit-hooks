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

// errorGroup combines messages with equivalent output into a single card.
type errorGroup struct {
	step  string
	paths []string
	raw   string
}

// groupMessages deduplicates messages by normalizing relative path prefixes
// in the output so that "../../../regional/main.tofu" matches "regional/main.tofu".
func groupMessages(msgs []TofuMessage) []*errorGroup {
	var groups []*errorGroup
	seen := map[string]*errorGroup{}

	for _, msg := range msgs {
		key := msg.Step + "\x00" + strings.ReplaceAll(msg.Output, "../", "")
		if g, ok := seen[key]; ok {
			g.paths = append(g.paths, msg.RelPath)
		} else {
			g = &errorGroup{step: msg.Step, paths: []string{msg.RelPath}, raw: msg.Output}
			seen[key] = g
			groups = append(groups, g)
		}
	}
	return groups
}

// PrintWarningSummary prints warning messages as styled cards,
// deduplicating equivalent warnings across directories.
func PrintWarningSummary(warningMessages []TofuMessage) {
	if len(warningMessages) == 0 {
		return
	}

	groups := groupMessages(warningMessages)
	for i, g := range groups {
		c := NewCard(Yellow)
		c.Open(Badge("WARNING", BoldYellow), Title("OpenTofu "+g.step))
		for _, p := range g.paths {
			c.Line(fmt.Sprintf("%s %s", File, Colorize(p, Gray)))
		}
		c.Blank()

		lines := strings.Split(g.raw, "\n")
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
		if i < len(groups)-1 {
			fmt.Println()
		}
	}
}

// PrintErrorSummary prints error messages as styled cards,
// deduplicating equivalent errors across directories.
func PrintErrorSummary(errorMessages []TofuMessage) {
	if len(errorMessages) == 0 {
		return
	}

	groups := groupMessages(errorMessages)
	for i, g := range groups {
		c := NewCard(Red)
		c.Open(Badge("ERROR", BoldRed), Title("OpenTofu "+g.step+" failed"))
		for _, p := range g.paths {
			c.Line(fmt.Sprintf("%s %s", File, Colorize(p, Gray)))
		}
		c.Blank()

		lines := strings.Split(g.raw, "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				c.Line(fmt.Sprintf("%s%s%s", Dim, line, Reset))
			}
		}
		c.Close()
		if i < len(groups)-1 {
			fmt.Println()
		}
	}
}
