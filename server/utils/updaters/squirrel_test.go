package updaters

import "testing"

func TestRewriteReleasesToAbsoluteURLs(t *testing.T) {
	base := "https://faynosync-connectycube.s3.amazonaws.com/squirrel_windows/app-admin/0.0.1/nightly/win32/x64"

	input := "0A6D7FD9 faynosync-squirrel-example-0.0.1-full.nupkg 108579388\n" +
		"37BDE1F0 faynosync-squirrel-example-0.0.2-full.nupkg 108579386\n"

	want := "0A6D7FD9 " + base + "/faynosync-squirrel-example-0.0.1-full.nupkg 108579388\n" +
		"37BDE1F0 " + base + "/faynosync-squirrel-example-0.0.2-full.nupkg 108579386\n"

	if got := RewriteReleasesToAbsoluteURLs(input, base); got != want {
		t.Errorf("rewrite mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestRewriteReleasesPreservesAbsoluteAndMalformed(t *testing.T) {
	base := "https://example.com/dir"

	already := "0A6D7FD9 https://cdn.example.com/pkg-full.nupkg 100"
	if got := RewriteReleasesToAbsoluteURLs(already, base); got != already {
		t.Errorf("already-absolute line should be unchanged, got %q", got)
	}

	malformed := "0A6D7FD9 pkg-full.nupkg"
	if got := RewriteReleasesToAbsoluteURLs(malformed, base); got != malformed {
		t.Errorf("line without 3 columns should be unchanged, got %q", got)
	}
}
