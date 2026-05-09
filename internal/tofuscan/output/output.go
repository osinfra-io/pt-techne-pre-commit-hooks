package output

import (
	"fmt"
	"os"
	"strings"

	"pre-commit-hooks/internal/tofuscan/engine"

	"golang.org/x/term"
)

// ANSI escape codes — disabled when stdout is not a terminal or NO_COLOR is set.
var (
	Reset      = "\033[0m"
	Bold       = "\033[1m"
	Dim        = "\033[2m"
	Red        = "\033[31m"
	BoldRed    = "\033[1;31m"
	BoldGreen  = "\033[1;32m"
	Yellow     = "\033[33m"
	BoldYellow = "\033[1;33m"
	Cyan       = "\033[36m"
	BoldCyan   = "\033[1;36m"
	BoldWhite  = "\033[1;97m"
	Gray       = "\033[38;5;245m" // medium gray for metadata
	DarkGray   = "\033[38;5;240m" // darker gray for secondary metadata
)

func init() {
	if !colorEnabled() {
		Reset = ""
		Bold = ""
		Dim = ""
		Red = ""
		BoldRed = ""
		BoldGreen = ""
		Yellow = ""
		BoldYellow = ""
		Cyan = ""
		BoldCyan = ""
		BoldWhite = ""
		Gray = ""
		DarkGray = ""
	}
}

func colorEnabled() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// Emoji constants.
const (
	EmojiSkull   = "💀"
	EmojiCheck   = "👍"
	EmojiFile    = "📄"
	EmojiTag     = "🏷 "
)

const descWrapWidth = 76

// Print writes violations to stdout. skippedCount is included in the summary
// line so users know how many violations were suppressed by skip comments.
func Print(violations []engine.Violation, skippedCount int) {
	if len(violations) == 0 {
		msg := "No violations found"
		if skippedCount > 0 {
			msg += fmt.Sprintf(" (%d skipped)", skippedCount)
		}
		fmt.Printf("%s %s%s%s\n", EmojiCheck, BoldGreen, msg, Reset)
		return
	}

	files := make(map[string]bool)
	for _, v := range violations {
		if v.File != "" {
			files[v.File] = true
		}
	}

	for i, v := range violations {
		printViolation(v)
		if i < len(violations)-1 {
			fmt.Println()
		}
	}

	fmt.Println()
	count := len(violations)
	fileCount := len(files)
	summary := fmt.Sprintf("%d violation(s) found across %d file(s)", count, fileCount)
	if skippedCount > 0 {
		summary += fmt.Sprintf(" (%d skipped)", skippedCount)
	}
	fmt.Printf("%s %s%s%s\n", EmojiSkull, BoldRed, summary, Reset)
}

func printViolation(v engine.Violation) {
	col := severityColor(v.Severity)
	boldCol := severityBoldColor(v.Severity)

	border := func(s string) string { return fmt.Sprintf("%s%s%s", col, s, Reset) }

	// Budget for the file path: terminal width minus the fixed prefix
	// ("│  📄 " ≈ 7 visible chars) and any suffix text.
	tw := termWidth()

	var fileRef string
	switch {
	case v.Line > 0:
		lineStr := fmt.Sprintf(":%d", v.Line)
		maxPath := tw - 7 - len(lineStr)
		p := truncatePath(v.File, maxPath)
		fileRef = fmt.Sprintf("%s%s:%d%s", Gray, p, v.Line, Reset)
	case v.File == "":
		fileRef = fmt.Sprintf("%s(project-level check)%s", DarkGray, Reset)
	default:
		suffix := "  (resource absent from file)"
		maxPath := tw - 7 - len(suffix)
		p := truncatePath(v.File, maxPath)
		fileRef = fmt.Sprintf("%s%s  %s(resource absent from file)%s", Gray, p, DarkGray, Reset)
	}

	badge := fmt.Sprintf("%s[%s]%s", boldCol, strings.ToUpper(v.Severity), Reset)
	title := fmt.Sprintf("%s%s%s", BoldWhite, v.Title, Reset)

	fmt.Printf("%s %s %s\n", border("╭─"), badge, title)
	fmt.Printf("%s  %s %s\n", border("│"), EmojiFile, fileRef)
	benchmark := "GCP CIS"
	if strings.HasPrefix(v.RuleID, "gke/") {
		benchmark = "GKE CIS"
	}
	cisLine := fmt.Sprintf("%s%s %s%s", boldCol, benchmark, v.CISControl, Reset)
	if v.ProfileLevel != "" {
		cisLine += fmt.Sprintf("  %s%s%s", DarkGray, v.ProfileLevel, Reset)
	}
	fmt.Printf("%s  %s %s%s%s · %s\n",
		border("│"), EmojiTag,
		Gray, cisSectionName(v.RuleID, v.CISControl), Reset,
		cisLine,
	)

	if v.Description != "" {
		fmt.Printf("%s\n", border("│"))
		for _, line := range wrapText(v.Description, descWrapWidth) {
			fmt.Printf("%s  %s%s%s\n", border("│"), Dim, line, Reset)
		}
	}

	fmt.Printf("%s\n", border("╰─"))
}

// wrapText wraps text at word boundaries for the given width.
func wrapText(text string, width int) []string {
	words := strings.Fields(text)
	var lines []string
	var current strings.Builder

	for _, word := range words {
		if current.Len() > 0 && current.Len()+1+len(word) > width {
			lines = append(lines, current.String())
			current.Reset()
		}
		if current.Len() > 0 {
			current.WriteByte(' ')
		}
		current.WriteString(word)
	}
	if current.Len() > 0 {
		lines = append(lines, current.String())
	}
	return lines
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
		return Red
	case "Medium":
		return Yellow
	default:
		return Cyan
	}
}

func severityBoldColor(severity string) string {
	switch severity {
	case "High":
		return BoldRed
	case "Medium":
		return BoldYellow
	default:
		return BoldCyan
	}
}

// termWidth returns the terminal width, defaulting to 80 if detection fails.
func termWidth() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 {
		return 80
	}
	return w
}

// truncatePath shortens a file path to fit within maxLen visible characters
// by replacing the middle of the path with "…", preserving the leading
// directory context and filename.
func truncatePath(path string, maxLen int) string {
	if len(path) <= maxLen || maxLen < 10 {
		return path
	}
	// Keep the filename (last component) plus some leading context.
	lastSlash := strings.LastIndex(path, "/")
	tail := path
	if lastSlash >= 0 {
		tail = path[lastSlash:]
	}
	// If the tail alone is too long, just hard-truncate.
	if len(tail)+4 >= maxLen {
		return path[:maxLen-1] + "…"
	}
	headLen := maxLen - len(tail) - 1 // 1 visible char for …
	return path[:headLen] + "…" + tail
}
