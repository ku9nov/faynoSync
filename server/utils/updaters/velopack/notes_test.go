package velopack

import (
	"strings"
	"testing"
)

func TestRenderNotesHTML_RendersMarkdown(t *testing.T) {
	html := RenderNotesHTML("# Title\n\n- one\n- two\n\n[docs](https://faynosync.com)")
	for _, want := range []string{"<h1>Title</h1>", "<li>one</li>", `href="https://faynosync.com"`} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected %q in output, got: %s", want, html)
		}
	}
}

func TestRenderNotesHTML_Empty(t *testing.T) {
	if got := RenderNotesHTML("   \n  "); got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestRenderNotesHTML_StripsScript(t *testing.T) {
	html := RenderNotesHTML("hello\n\n<script>alert(1)</script>")
	if strings.Contains(strings.ToLower(html), "<script") {
		t.Fatalf("script tag must be stripped, got: %s", html)
	}
}

func TestRenderNotesHTML_StripsJavascriptHref(t *testing.T) {
	html := RenderNotesHTML("[click](javascript:alert(1))")
	if strings.Contains(strings.ToLower(html), "javascript:") {
		t.Fatalf("javascript: scheme must be stripped, got: %s", html)
	}
}

func TestRenderNotesHTML_StripsImgOnerror(t *testing.T) {
	html := RenderNotesHTML("![x](https://e.com/a.png)\n\n<img src=x onerror=alert(1)>")
	if strings.Contains(strings.ToLower(html), "onerror") {
		t.Fatalf("event handler must be stripped, got: %s", html)
	}
}
