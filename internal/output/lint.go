package output

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	lintLocationPattern = regexp.MustCompile(`^on (.+) line ([0-9]+)`)
	lintSourcePattern   = regexp.MustCompile(`^[0-9]+:`)
)

type lintFinding struct {
	title       string
	rule        string
	location    string
	description []string
}

func parseLintFindings(raw string) []lintFinding {
	var findings []lintFinding
	var current *lintFinding
	for _, line := range strings.Split(cleanLintOutput(raw), "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "warning:") {
			title := strings.TrimSpace(line[len("warning:"):])
			rule := ""
			if start := strings.LastIndex(title, " ("); start >= 0 && strings.HasSuffix(title, ")") {
				rule = title[start+2 : len(title)-1]
				title = title[:start]
			}
			findings = append(findings, lintFinding{title: title, rule: rule})
			current = &findings[len(findings)-1]
			continue
		}
		if strings.HasPrefix(lower, "error:") {
			current = nil
		}
		if current == nil || line == "" {
			continue
		}
		if match := lintLocationPattern.FindStringSubmatch(line); match != nil {
			current.location = match[1] + ":" + match[2]
			continue
		}
		if lintSourcePattern.MatchString(line) {
			continue
		}
		current.description = append(current.description, line)
	}
	return findings
}

// PrintLintWarningSummary renders individual findings using the scan card layout.
func PrintLintWarningSummary(messages []TofuMessage) {
	// Only combine messages with identical locations as well as diagnostics.
	var groups []*errorGroup
	seen := make(map[string]*errorGroup)
	for _, message := range messages {
		raw := cleanLintOutput(message.Output)
		key := message.Step + "\x00" + raw
		if group, ok := seen[key]; ok {
			group.paths = append(group.paths, message.RelPath)
		} else {
			group := &errorGroup{paths: []string{message.RelPath}, raw: raw}
			seen[key] = group
			groups = append(groups, group)
		}
	}
	printed := false
	for _, group := range groups {
		for _, finding := range parseLintFindings(group.raw) {
			if printed {
				fmt.Println()
			}
			printed = true
			card := NewCard(Yellow)
			card.Open(Badge("WARNING", BoldYellow), Title(finding.title))
			for _, path := range group.paths {
				location := path
				if finding.location != "" {
					location = filepath.ToSlash(filepath.Join(path, finding.location))
				}
				card.Line(fmt.Sprintf("%s %s", File, Colorize(location, Gray)))
			}
			if finding.rule != "" {
				card.Line(fmt.Sprintf("%s %s", Tag, Colorize(finding.rule, Gray)))
			}
			if len(finding.description) > 0 {
				card.Blank()
				for _, line := range WrapText(strings.Join(finding.description, " "), 76) {
					card.Line(Colorize(line, Dim))
				}
			}
			card.Close()
		}
	}
}
