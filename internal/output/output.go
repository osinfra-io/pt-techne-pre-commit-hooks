package output

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// ANSI escape codes — disabled when stdout is not a terminal or NO_COLOR is set.
var (
	Reset      = "\033[0m"
	Bold       = "\033[1m"
	Dim        = "\033[2m"
	Red        = "\033[31m"
	Green      = "\033[32m"
	Yellow     = "\033[33m"
	Cyan       = "\033[36m"
	BoldRed    = "\033[1;31m"
	BoldGreen  = "\033[1;32m"
	BoldYellow = "\033[1;33m"
	BoldCyan   = "\033[1;36m"
	BoldWhite  = "\033[1;97m"
	Gray       = "\033[38;5;245m"
	DarkGray   = "\033[38;5;240m"
)

func init() {
	if !ColorEnabled() {
		disableColors()
	}
}

// ColorEnabled reports whether color output should be used.
func ColorEnabled() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// EnableColor forces all color codes on. Useful in tests that assert ANSI output.
func EnableColor() {
	Reset = "\033[0m"
	Bold = "\033[1m"
	Dim = "\033[2m"
	Red = "\033[31m"
	Green = "\033[32m"
	Yellow = "\033[33m"
	Cyan = "\033[36m"
	BoldRed = "\033[1;31m"
	BoldGreen = "\033[1;32m"
	BoldYellow = "\033[1;33m"
	BoldCyan = "\033[1;36m"
	BoldWhite = "\033[1;97m"
	Gray = "\033[38;5;245m"
	DarkGray = "\033[38;5;240m"
}

func disableColors() {
	Reset = ""
	Bold = ""
	Dim = ""
	Red = ""
	Green = ""
	Yellow = ""
	Cyan = ""
	BoldRed = ""
	BoldGreen = ""
	BoldYellow = ""
	BoldCyan = ""
	BoldWhite = ""
	Gray = ""
	DarkGray = ""
}

// Emoji constants.
const (
	Error    = "💀"
	Warning  = "🚧"
	Running  = "🔧"
	ThumbsUp = "👍"
	File     = "📄"
	Tag      = "🏷 "
)

// Colorize wraps text with the given color and a Reset suffix.
func Colorize(text, color string) string {
	return fmt.Sprintf("%s%s%s", color, text, Reset)
}

// EmojiColorText combines an emoji with colored text.
func EmojiColorText(emoji, text, color string) string {
	return fmt.Sprintf("%s %s", emoji, Colorize(text, color))
}

// TermWidth returns the terminal width, defaulting to 80 if detection fails.
func TermWidth() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 {
		return 80
	}
	return w
}
