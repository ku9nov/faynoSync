package storage

import "testing"

// The public artifact link is built from the object key, so the key has to be escaped
// per path segment: "/" must stay a separator while spaces and other unsafe characters
// are escaped, or the stored link points at a different object than the uploaded one.
func TestEncodeObjectKeyForPublicURL(t *testing.T) {
	cases := map[string]string{
		"MyApp-acme/nightly/darwin/arm64/MyApp-1.0.0.dmg":    "MyApp-acme/nightly/darwin/arm64/MyApp-1.0.0.dmg",
		"MyApp-acme/nightly/My App 1.0.0.dmg":                "MyApp-acme/nightly/My%20App%201.0.0.dmg",
		"/MyApp-acme/nightly/MyApp.dmg":                      "MyApp-acme/nightly/MyApp.dmg",
		"MyApp-acme/nightly/MyApp?1.0.0.dmg":                 "MyApp-acme/nightly/MyApp%3F1.0.0.dmg",
		"MyApp-acme/nightly/MyApp#1.0.0.dmg":                 "MyApp-acme/nightly/MyApp%231.0.0.dmg",
		"velopack/acme/MyApp/win/x64/MyApp-1.0.0-full.nupkg": "velopack/acme/MyApp/win/x64/MyApp-1.0.0-full.nupkg",
	}

	for key, want := range cases {
		if got := encodeObjectKeyForPublicURL(key); got != want {
			t.Errorf("encodeObjectKeyForPublicURL(%q) = %q, want %q", key, got, want)
		}
	}
}
