package velopack

import (
	"bytes"
	"strings"

	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
)

var (
	notesRenderer = goldmark.New()
	notesPolicy   = bluemonday.UGCPolicy()
)

// RenderNotesHTML converts a changelog markdown string into sanitized HTML for the velopack feed NotesHTML field.
func RenderNotesHTML(markdown string) string {
	if strings.TrimSpace(markdown) == "" {
		return ""
	}
	var buf bytes.Buffer
	if err := notesRenderer.Convert([]byte(markdown), &buf); err != nil {
		return ""
	}
	return notesPolicy.Sanitize(buf.String())
}
