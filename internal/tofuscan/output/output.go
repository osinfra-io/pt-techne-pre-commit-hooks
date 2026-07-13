package output

import (
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"sync"

	"pre-commit-hooks/internal/output"
	"pre-commit-hooks/internal/tofuscan/engine"
	"pre-commit-hooks/internal/tofuscan/policies"
)

const descWrapWidth = 76

// RuleMetadata holds static metadata about a policy rule, parsed from .rego files.
type RuleMetadata struct {
	RuleID       string
	CISControl   string
	ProfileLevel string
	Severity     string
	Title        string
	Description  string
}

var (
	ruleMetadataOnce sync.Once
	ruleResourceMap  map[string]map[string]struct{} // rule_id → resource types
	ruleMetadataMap  map[string]*RuleMetadata       // rule_id → metadata

	ruleIDPattern       = regexp.MustCompile(`"rule_id"\s*:\s*"([^"]+)"`)
	resourcePattern     = regexp.MustCompile(`input\.resource\.(\w+)`)
	cisControlPattern   = regexp.MustCompile(`"cis_control"\s*:\s*"([^"]+)"`)
	profileLevelPattern = regexp.MustCompile(`"profile_level"\s*:\s*"([^"]+)"`)
	severityPattern     = regexp.MustCompile(`"severity"\s*:\s*"([^"]+)"`)
	titlePattern        = regexp.MustCompile(`"title"\s*:\s*"([^"]+)"`)
	titleConcatPattern  = regexp.MustCompile(`(?s)_title_\w+\s*:=\s*concat\("",\s*\[(.*?)\]\)`)
	descConcatPattern   = regexp.MustCompile(`(?s)_desc_\w+\s*:=\s*concat\("",\s*\[(.*?)\]\)`)
	concatPartPattern   = regexp.MustCompile(`"([^"]+)"`)
)

// Print writes violations, skipped violations, and passing rules to stdout.
func Print(violations []engine.Violation, skipped []engine.Violation, resourceTypes map[string]struct{}) {
	printed := false

	// Print passing rule cards first.
	passingRules := computePassingRules(violations, skipped, resourceTypes)
	for _, meta := range passingRules {
		if printed {
			fmt.Println()
		}
		printPassingCard(meta)
		printed = true
	}

	// Print failing violation cards sorted by severity ascending (low → medium → high).
	sorted := sortBySeverity(violations)
	for _, v := range sorted {
		if printed {
			fmt.Println()
		}
		printViolation(v)
		printed = true
	}

	// Print skipped violations in light gray.
	if len(skipped) > 0 {
		if printed {
			fmt.Println()
		}
		for _, v := range skipped {
			printSkippedViolation(v)
		}
		printed = true
	}

	// Summary line.
	if printed {
		fmt.Println()
	}
	printSummary(violations, skipped, resourceTypes)
}

func printSkippedViolation(v engine.Violation) {
	benchmark := "GCP CIS"
	if strings.HasPrefix(v.RuleID, "gke/") {
		benchmark = "GKE CIS"
	}
	fmt.Printf("%s── [SKIPPED] %s · %s %s%s\n",
		output.DarkGray, v.Title,
		benchmark, v.CISControl, output.Reset,
	)
}

func printSummary(violations, skipped []engine.Violation, resourceTypes map[string]struct{}) {
	var highCount, mediumCount int
	files := make(map[string]bool)
	for _, v := range violations {
		switch v.Severity {
		case "High":
			highCount++
		case "Medium":
			mediumCount++
		}
		if v.File != "" {
			files[v.File] = true
		}
	}

	total := len(violations)
	skippedCount := len(skipped)
	passedCount, hasPassedCount := computePassedRulesCount(violations, skipped, resourceTypes)

	checked := total + passedCount
	if !hasPassedCount {
		checked = 0
	}

	// Ratio line: 🛡️ 19/22 rules passed  ·  1 file scanned
	emoji := summaryEmoji(passedCount, checked)
	if hasPassedCount && checked > 0 {
		line := fmt.Sprintf("%s %s%d/%d rules passed%s", emoji, output.BoldWhite, passedCount, checked, output.Reset)
		if len(files) > 0 {
			line += fmt.Sprintf("  ·  %s%d file(s) scanned%s", output.DarkGray, len(files), output.Reset)
		}
		fmt.Println(line)
	} else if total == 0 {
		fmt.Printf("%s %s%s%s\n", output.ThumbsUp, output.BoldGreen, "No violations found", output.Reset)
		return
	}

	// Failure breakdown on separate lines.
	if highCount > 0 {
		fmt.Printf("     • %s%d high%s\n", output.BoldRed, highCount, output.Reset)
	}
	if mediumCount > 0 {
		fmt.Printf("     • %s%d medium%s\n", output.BoldYellow, mediumCount, output.Reset)
	}
	if skippedCount > 0 {
		fmt.Printf("     • %s%d skipped%s\n", output.DarkGray, skippedCount, output.Reset)
	}
}

func summaryEmoji(passed, total int) string {
	if total == 0 {
		return output.ThumbsUp
	}
	pct := float64(passed) / float64(total) * 100
	switch {
	case pct >= 85:
		return "🛡️"
	case pct >= 50:
		return output.Warning
	default:
		return output.Error
	}
}

func printViolation(v engine.Violation) {
	col := severityColor(v.Severity)
	boldCol := severityBoldColor(v.Severity)

	c := output.NewCard(col)
	tw := output.TermWidth()

	var fileRef string
	switch {
	case v.Line > 0:
		lineStr := fmt.Sprintf(":%d", v.Line)
		maxPath := tw - 7 - len(lineStr)
		p := truncatePath(v.File, maxPath)
		fileRef = fmt.Sprintf("%s%s:%d%s", output.Gray, p, v.Line, output.Reset)
	case v.File == "":
		fileRef = fmt.Sprintf("%s(project-level check)%s", output.DarkGray, output.Reset)
	default:
		suffix := "  (resource absent from file)"
		maxPath := tw - 7 - len(suffix)
		p := truncatePath(v.File, maxPath)
		fileRef = fmt.Sprintf("%s%s  %s(resource absent from file)%s", output.Gray, p, output.DarkGray, output.Reset)
	}

	badge := output.Badge("FAIL", boldCol)
	title := output.Title(v.Title)

	c.Open(badge, title)
	c.Line(fmt.Sprintf("%s %s", output.File, fileRef))
	printCISLine(c, v.RuleID, v.CISControl, v.ProfileLevel, v.Severity)

	if v.Description != "" {
		c.Blank()
		for _, line := range output.WrapText(v.Description, descWrapWidth) {
			c.Line(fmt.Sprintf("%s%s%s", output.Dim, line, output.Reset))
		}
	}

	c.Close()
}

func printPassingCard(meta *RuleMetadata) {
	c := output.NewCard(output.Green)
	badge := output.Badge("PASS", output.BoldGreen)
	title := output.Title(meta.Title)

	c.Open(badge, title)
	printCISLine(c, meta.RuleID, meta.CISControl, meta.ProfileLevel, meta.Severity)

	if meta.Description != "" {
		c.Blank()
		for _, line := range output.WrapText(meta.Description, descWrapWidth) {
			c.Line(fmt.Sprintf("%s%s%s", output.Dim, line, output.Reset))
		}
	}

	c.Close()
}

func printCISLine(c *output.Card, ruleID, cisControl, profileLevel, severity string) {
	benchmark := "GCP CIS"
	if strings.HasPrefix(ruleID, "gke/") {
		benchmark = "GKE CIS"
	}
	cisCol := severityBoldColor(severity)
	cisLine := fmt.Sprintf("%s%s %s%s", cisCol, benchmark, cisControl, output.Reset)
	if profileLevel != "" {
		cisLine += fmt.Sprintf("  %s%s%s", output.DarkGray, profileLevel, output.Reset)
	}
	c.Line(fmt.Sprintf("%s %s%s%s · %s",
		output.Tag,
		output.Gray, cisSectionName(ruleID, cisControl), output.Reset,
		cisLine,
	))
}

// cisSectionName maps a CIS control to its benchmark section name.
func cisSectionName(ruleID, control string) string {
	if strings.HasPrefix(ruleID, "gke/") {
		return gkeSectionName(control)
	}
	return gcpSectionName(control)
}

// gcpSectionName maps GCP CIS control numbers to section names.
func gcpSectionName(control string) string {
	if len(control) == 0 {
		return ""
	}
	switch control[0] {
	case '1':
		return "Identity and Access Management"
	case '2':
		return "Logging and Monitoring"
	case '3':
		return "Networking"
	case '4':
		return "Virtual Machines"
	case '5':
		return "Storage"
	case '6':
		return "Cloud SQL"
	case '7':
		return "BigQuery"
	case '8':
		return "Dataproc"
	default:
		return control
	}
}

// gkeSectionName maps GKE CIS control numbers (e.g. "5.6.3") to section names.
func gkeSectionName(control string) string {
	parts := strings.SplitN(control, ".", 3)
	if len(parts) < 2 {
		return control
	}
	switch parts[1] {
	case "1":
		return "Image Registry and Scanning"
	case "2":
		return "Identity and Access Management"
	case "3":
		return "Cloud KMS"
	case "4":
		return "Node Metadata"
	case "5":
		return "Node Configuration"
	case "6":
		return "Cluster Networking"
	case "7":
		return "Logging"
	case "8":
		return "Authentication and Authorization"
	case "9":
		return "Storage"
	case "10":
		return "Other Cluster Configurations"
	default:
		return control
	}
}

func severityColor(severity string) string {
	switch severity {
	case "High":
		return output.Red
	case "Medium":
		return output.Yellow
	default:
		return output.Cyan
	}
}

func severityBoldColor(severity string) string {
	switch severity {
	case "High":
		return output.BoldRed
	case "Medium":
		return output.BoldYellow
	default:
		return output.BoldCyan
	}
}

func severityOrder(severity string) int {
	switch severity {
	case "Low":
		return 0
	case "Medium":
		return 1
	case "High":
		return 2
	default:
		return -1
	}
}

func profileLevelOrder(level string) int {
	switch level {
	case "Level 1":
		return 1
	case "Level 2":
		return 2
	default:
		return 0
	}
}

func sortBySeverity(violations []engine.Violation) []engine.Violation {
	sorted := make([]engine.Violation, len(violations))
	copy(sorted, violations)
	sort.SliceStable(sorted, func(i, j int) bool {
		si, sj := severityOrder(sorted[i].Severity), severityOrder(sorted[j].Severity)
		if si != sj {
			return si < sj
		}
		return profileLevelOrder(sorted[i].ProfileLevel) < profileLevelOrder(sorted[j].ProfileLevel)
	})
	return sorted
}

// truncatePath shortens a file path to fit within maxLen visible characters
// by replacing the middle of the path with "…", preserving the leading
// directory context and filename.
func truncatePath(path string, maxLen int) string {
	if len(path) <= maxLen || maxLen < 10 {
		return path
	}
	lastSlash := strings.LastIndex(path, "/")
	tail := path
	if lastSlash >= 0 {
		tail = path[lastSlash:]
	}
	if len(tail)+4 >= maxLen {
		return path[:maxLen-1] + "…"
	}
	headLen := maxLen - len(tail) - 1
	return path[:headLen] + "…" + tail
}

// applicableRuleIDs returns the set of rule IDs whose associated resource types
// overlap with resourceTypes. Caller must have called initRuleMetadata() first.
func applicableRuleIDs(resourceTypes map[string]struct{}) map[string]struct{} {
	matched := make(map[string]struct{})
	for ruleID, ruleTypes := range ruleResourceMap {
		for rt := range ruleTypes {
			if _, present := resourceTypes[rt]; present {
				matched[ruleID] = struct{}{}
				break
			}
		}
	}
	return matched
}

// computePassingRules returns metadata for rules that matched scanned
// resource types but produced no violations and were not skipped.
func computePassingRules(violations, skipped []engine.Violation, resourceTypes map[string]struct{}) []*RuleMetadata {
	if len(resourceTypes) == 0 {
		return nil
	}

	initRuleMetadata()
	if len(ruleResourceMap) == 0 {
		return nil
	}

	failedRules := make(map[string]struct{})
	for _, v := range append(violations, skipped...) {
		if v.RuleID != "" {
			failedRules[v.RuleID] = struct{}{}
		}
	}

	var passing []*RuleMetadata
	for ruleID := range applicableRuleIDs(resourceTypes) {
		if _, failed := failedRules[ruleID]; failed {
			continue
		}
		if meta, ok := ruleMetadataMap[ruleID]; ok {
			passing = append(passing, meta)
		}
	}

	sort.Slice(passing, func(i, j int) bool {
		si, sj := severityOrder(passing[i].Severity), severityOrder(passing[j].Severity)
		if si != sj {
			return si < sj
		}
		li, lj := profileLevelOrder(passing[i].ProfileLevel), profileLevelOrder(passing[j].ProfileLevel)
		if li != lj {
			return li < lj
		}
		return passing[i].RuleID < passing[j].RuleID
	})
	return passing
}

func computePassedRulesCount(violations, skipped []engine.Violation, resourceTypes map[string]struct{}) (int, bool) {
	if len(resourceTypes) == 0 {
		return 0, false
	}

	initRuleMetadata()
	if len(ruleResourceMap) == 0 {
		return 0, false
	}

	matched := applicableRuleIDs(resourceTypes)
	if len(matched) == 0 {
		return 0, false
	}

	failedRules := make(map[string]struct{})
	for _, v := range append(violations, skipped...) {
		if v.RuleID != "" {
			if _, ok := matched[v.RuleID]; ok {
				failedRules[v.RuleID] = struct{}{}
			}
		}
	}

	passed := len(matched) - len(failedRules)
	if passed < 0 {
		passed = 0
	}
	return passed, true
}

// getRuleResourceMap returns a mapping of rule_id → set of resource types
// referenced in the embedded policy files.
func getRuleResourceMap() map[string]map[string]struct{} {
	initRuleMetadata()
	return ruleResourceMap
}

func initRuleMetadata() {
	ruleMetadataOnce.Do(func() {
		ruleResourceMap = make(map[string]map[string]struct{})
		ruleMetadataMap = make(map[string]*RuleMetadata)

		_ = fs.WalkDir(policies.FS, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".rego") || strings.HasSuffix(path, "_test.rego") {
				return nil
			}

			content, readErr := fs.ReadFile(policies.FS, path)
			if readErr != nil {
				return nil
			}

			text := string(content)

			ruleIDs := make(map[string]struct{})
			for _, match := range ruleIDPattern.FindAllStringSubmatch(text, -1) {
				if len(match) > 1 && match[1] != "" {
					ruleIDs[match[1]] = struct{}{}
				}
			}

			resTypes := make(map[string]struct{})
			for _, match := range resourcePattern.FindAllStringSubmatch(text, -1) {
				if len(match) > 1 && match[1] != "" {
					resTypes[match[1]] = struct{}{}
				}
			}

			for ruleID := range ruleIDs {
				if _, exists := ruleResourceMap[ruleID]; !exists {
					ruleResourceMap[ruleID] = make(map[string]struct{})
				}
				for rt := range resTypes {
					ruleResourceMap[ruleID][rt] = struct{}{}
				}

				if _, exists := ruleMetadataMap[ruleID]; !exists {
					ruleMetadataMap[ruleID] = &RuleMetadata{
						RuleID:       ruleID,
						CISControl:   firstMatch(cisControlPattern, text),
						ProfileLevel: firstMatch(profileLevelPattern, text),
						Severity:     firstMatch(severityPattern, text),
						Title:        extractTitle(text),
						Description:  extractConcat(descConcatPattern, text),
					}
				}
			}
			return nil
		})
	})
}

func firstMatch(re *regexp.Regexp, text string) string {
	m := re.FindStringSubmatch(text)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

// extractTitle returns the title from a .rego file, handling both inline
// string literals ("title": "...") and concat variable references
// (_title_X := concat("", [...])).
func extractTitle(text string) string {
	if t := firstMatch(titlePattern, text); t != "" {
		return t
	}
	return extractConcat(titleConcatPattern, text)
}

// extractConcat extracts a string built via concat("", [...]) in a .rego file.
func extractConcat(pattern *regexp.Regexp, text string) string {
	m := pattern.FindStringSubmatch(text)
	if len(m) < 2 {
		return ""
	}
	parts := concatPartPattern.FindAllStringSubmatch(m[1], -1)
	var sb strings.Builder
	for _, p := range parts {
		if len(p) > 1 {
			sb.WriteString(p[1])
		}
	}
	return sb.String()
}
