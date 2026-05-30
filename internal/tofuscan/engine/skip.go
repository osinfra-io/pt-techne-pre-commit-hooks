package engine

import (
	"bufio"
	"os"
	"strings"
)

// SkipDirectives holds parsed skip comments from source files.
type SkipDirectives struct {
	// resourceLevel maps file path → resource name → CIS control → reason.
	resourceLevel map[string]map[string]map[string]string
}

// ParseSkipDirectives scans the given files for tofu-scan skip comments.
//
// Skip comments must be placed inside the resource block they apply to:
//
//	resource "google_container_cluster" "primary" {
//	  # tofu-scan skip: CIS 5.6.4 - Not applicable to this project
//	  name = "test"
//	}
//
// Comments outside resource blocks are ignored.
func ParseSkipDirectives(files []string) *SkipDirectives {
	sd := &SkipDirectives{
		resourceLevel: make(map[string]map[string]map[string]string),
	}
	seen := make(map[string]bool)
	for _, file := range files {
		if seen[file] || file == "" {
			continue
		}
		seen[file] = true
		resLvl := parseFileSkips(file)
		if len(resLvl) > 0 {
			sd.resourceLevel[file] = resLvl
		}
	}
	return sd
}

// Filter partitions violations into kept and skipped based on skip directives.
func (sd *SkipDirectives) Filter(violations []Violation) (kept, skipped []Violation) {
	for _, v := range violations {
		if sd.shouldSkip(v) {
			skipped = append(skipped, v)
		} else {
			kept = append(kept, v)
		}
	}
	return kept, skipped
}

func (sd *SkipDirectives) shouldSkip(v Violation) bool {
	if resSkips, ok := sd.resourceLevel[v.File]; ok {
		if skips, ok := resSkips[v.Resource]; ok {
			if _, ok := skips[v.CISControl]; ok {
				return true
			}
		}
	}
	return false
}

// parseFileSkips scans a single file for skip comments inside resource blocks
// using lightweight brace tracking. Skip comments outside resource blocks
// are ignored.
func parseFileSkips(file string) map[string]map[string]string {
	resourceLevel := make(map[string]map[string]string)

	f, err := os.Open(file)
	if err != nil {
		return resourceLevel
	}
	defer func() { _ = f.Close() }()

	var (
		currentResource string
		braceDepth      int
	)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		trimmed := strings.TrimSpace(scanner.Text())

		// Check for skip comment — only relevant inside a resource block.
		if currentResource != "" {
			if control, reason := parseSkipComment(trimmed); control != "" {
				if resourceLevel[currentResource] == nil {
					resourceLevel[currentResource] = make(map[string]string)
				}
				resourceLevel[currentResource][control] = reason
				continue
			}
		}

		// Check for resource declaration (only at top level).
		if braceDepth == 0 && strings.HasPrefix(trimmed, "resource ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 {
				name := strings.Trim(parts[2], `"{}`)
				currentResource = name
				braceDepth += countBraces(trimmed)
				continue
			}
		}

		// Track brace depth for resource blocks.
		if currentResource != "" {
			braceDepth += countBraces(trimmed)
			if braceDepth <= 0 {
				currentResource = ""
				braceDepth = 0
			}
		}
	}

	return resourceLevel
}

// countBraces returns the net brace count ({minus}) for a line, ignoring
// braces inside comments and quoted strings.
func countBraces(line string) int {
	n := 0
	inString := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if inString {
			switch ch {
			case '\\':
				i++ // skip escaped character
			case '"':
				inString = false
			}
			continue
		}
		switch ch {
		case '"':
			inString = true
		case '#':
			return n // rest of line is a comment
		case '/':
			if i+1 < len(line) && line[i+1] == '/' {
				return n // rest of line is a comment
			}
		case '{':
			n++
		case '}':
			n--
		}
	}
	return n
}

// parseSkipComment extracts a CIS control and optional reason from a skip
// comment. Returns empty strings if the line is not a skip comment.
//
// Format: # tofu-scan skip: CIS <control> [- <reason>]
func parseSkipComment(line string) (control, reason string) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "#") {
		return "", ""
	}
	after := strings.TrimSpace(trimmed[1:])

	const prefix = "tofu-scan skip:"
	if len(after) < len(prefix) || !strings.EqualFold(after[:len(prefix)], prefix) {
		return "", ""
	}
	rest := strings.TrimSpace(after[len(prefix):])

	// Expect "CIS" keyword followed by whitespace.
	if len(rest) < 4 || !strings.EqualFold(rest[:3], "CIS") || (rest[3] != ' ' && rest[3] != '\t') {
		return "", ""
	}
	rest = strings.TrimSpace(rest[3:])

	// Extract control number (first non-whitespace token).
	parts := strings.SplitN(rest, " ", 2)
	if len(parts) == 0 || parts[0] == "" {
		return "", ""
	}
	control = parts[0]

	// Extract optional reason after "-".
	if len(parts) > 1 {
		remainder := strings.TrimSpace(parts[1])
		if strings.HasPrefix(remainder, "- ") {
			reason = strings.TrimSpace(remainder[2:])
		} else if strings.HasPrefix(remainder, "-") {
			reason = strings.TrimSpace(remainder[1:])
		}
	}

	return control, reason
}
