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

// groupMessages deduplicates messages by extracting a fingerprint from the
// error/warning text, ignoring file paths and source-line references that
// differ across directories pointing at the same underlying issue.
func groupMessages(msgs []TofuMessage) []*errorGroup {
	var groups []*errorGroup
	seen := map[string]*errorGroup{}

	for _, msg := range msgs {
		key := msg.Step + "\x00" + errorFingerprint(msg.Output)
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

// errorFingerprint extracts a canonical key from tofu output by splitting
// into diagnostic blocks (╷…╵), keeping only error/description lines, and
// deduplicating identical blocks within the same output.
func errorFingerprint(output string) string {
	blocks := splitDiagnosticBlocks(output)
	var unique []string
	seen := map[string]bool{}
	for _, block := range blocks {
		key := normalizeBlock(block)
		if key != "" && !seen[key] {
			seen[key] = true
			unique = append(unique, key)
		}
	}
	if len(unique) == 0 {
		// Fallback for output without ╷…╵ framing.
		return strings.ReplaceAll(output, "../", "")
	}
	return strings.Join(unique, "\n")
}

// splitDiagnosticBlocks splits tofu output into the individual diagnostic
// blocks delimited by ╷ and ╵.
func splitDiagnosticBlocks(output string) []string {
	var blocks []string
	var current []string
	inBlock := false
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "╷" {
			inBlock = true
			current = nil
			continue
		}
		if trimmed == "╵" {
			if inBlock {
				blocks = append(blocks, strings.Join(current, "\n"))
			}
			inBlock = false
			continue
		}
		if inBlock {
			current = append(current, line)
		}
	}
	return blocks
}

// normalizeBlock extracts just the error type and description from a
// diagnostic block, stripping file references and source lines so that
// the same error from different directories produces the same key.
func normalizeBlock(block string) string {
	var parts []string
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		trimmed = strings.TrimLeft(trimmed, "│")
		trimmed = strings.TrimSpace(trimmed)
		if trimmed == "" {
			continue
		}
		// Skip file reference lines: "on main.tofu line 18, ..."
		if strings.HasPrefix(trimmed, "on ") {
			continue
		}
		// Skip source code lines: "18:   lifZecycle {"
		if len(trimmed) > 0 && trimmed[0] >= '0' && trimmed[0] <= '9' {
			continue
		}
		parts = append(parts, trimmed)
	}
	return strings.Join(parts, "\n")
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
