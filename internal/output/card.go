package output

import (
	"fmt"
	"strings"
)

// Card draws a styled terminal card with box-drawing borders.
//
//	╭─ [BADGE] Title
//	│  content line
//	│
//	│  more content
//	╰─
type Card struct {
	color string
}

// NewCard creates a Card with the given border color.
func NewCard(borderColor string) *Card {
	return &Card{color: borderColor}
}

// Open prints the card header line.
func (c *Card) Open(badge, title string) {
	fmt.Printf("%s %s %s\n", c.border("╭─"), badge, title)
}

// Line prints a content line within the card.
func (c *Card) Line(text string) {
	fmt.Printf("%s  %s\n", c.border("│"), text)
}

// Blank prints an empty separator line within the card.
func (c *Card) Blank() {
	fmt.Println(c.border("│"))
}

// Close prints the card footer line.
func (c *Card) Close() {
	fmt.Println(c.border("╰─"))
}

func (c *Card) border(s string) string {
	return fmt.Sprintf("%s%s%s", c.color, s, Reset)
}

// Badge returns a colored badge string like [ERROR] or [WARNING].
func Badge(text, color string) string {
	return fmt.Sprintf("%s[%s]%s", color, text, Reset)
}

// Title returns a bold white title string.
func Title(text string) string {
	return fmt.Sprintf("%s%s%s", BoldWhite, text, Reset)
}

// WrapText wraps text at word boundaries for the given width.
func WrapText(text string, width int) []string {
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
