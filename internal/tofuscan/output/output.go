package output

import (
	"fmt"
	"strings"

	"pre-commit-hooks/internal/output"
	"pre-commit-hooks/internal/tofuscan/engine"
)

const descWrapWidth = 76

// Print writes violations and skipped violations to stdout.
func Print(violations []engine.Violation, skipped []engine.Violation) {
	if len(violations) == 0 && len(skipped) == 0 {
		fmt.Printf("%s %s%s%s\n", output.ThumbsUp, output.BoldGreen, "No violations found", output.Reset)
		return
	}

	// Print active violations.
	for i, v := range violations {
		printViolation(v)
		if i < len(violations)-1 {
			fmt.Println()
		}
	}

	// Print skipped violations in light gray.
	if len(skipped) > 0 {
		if len(violations) > 0 {
			fmt.Println()
		}
		for _, v := range skipped {
			printSkippedViolation(v)
		}
	}

	// Summary line with severity breakdown.
	fmt.Println()
	printSummary(violations, skipped)
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

func printSummary(violations, skipped []engine.Violation) {
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

	if total == 0 {
		msg := "No violations found"
		if skippedCount > 0 {
			msg += fmt.Sprintf("  %s%d skipped%s", output.DarkGray, skippedCount, output.Reset)
		}
		fmt.Printf("%s %s%s%s\n", output.ThumbsUp, output.BoldGreen, msg, output.Reset)
		return
	}

	fmt.Printf("%s %s%d violation(s) across %d file(s)%s\n",
		output.Error, output.BoldWhite, total, len(files), output.Reset)
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

	badge := output.Badge(strings.ToUpper(v.Severity), boldCol)
	title := output.Title(v.Title)

	c.Open(badge, title)
	c.Line(fmt.Sprintf("%s %s", output.File, fileRef))
	benchmark := "GCP CIS"
	if strings.HasPrefix(v.RuleID, "gke/") {
		benchmark = "GKE CIS"
	}
	cisLine := fmt.Sprintf("%s%s %s%s", boldCol, benchmark, v.CISControl, output.Reset)
	if v.ProfileLevel != "" {
		cisLine += fmt.Sprintf("  %s%s%s", output.DarkGray, v.ProfileLevel, output.Reset)
	}
	c.Line(fmt.Sprintf("%s %s%s%s · %s",
		output.Tag,
		output.Gray, cisSectionName(v.RuleID, v.CISControl), output.Reset,
		cisLine,
	))

	if v.Description != "" {
		c.Blank()
		for _, line := range output.WrapText(v.Description, descWrapWidth) {
			c.Line(fmt.Sprintf("%s%s%s", output.Dim, line, output.Reset))
		}
	}

	c.Close()
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
