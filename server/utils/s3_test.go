package utils

import (
	"net/url"
	"testing"

	"faynoSync/server/utils/updaters"
)

// Updater clients fetch these objects directly from storage and parse them by
// Content-Type, so the mapping is part of the feed contract, not a cosmetic header.
func TestGetContentType(t *testing.T) {
	cases := map[string]string{
		"RELEASES":              "text/plain",
		"releases":              "text/plain",
		"RELEASES.txt":          "",
		"latest.yml":            "text/yaml",
		"latest-mac.YAML":       "text/yaml",
		"releases.nightly.json": "application/json",
		"MyApp-1.0.0.dmg":       "",
		"MyApp-1.0.0.exe":       "",
		"":                      "",
	}

	for fileName, want := range cases {
		if got := getContentType(fileName); got != want {
			t.Errorf("getContentType(%q) = %q, want %q", fileName, got, want)
		}
	}
}

// The private artifact link is the only way back to the stored object: /download
// unescapes the key it carries, so it has to round-trip to the key that was uploaded.
func TestPrivateLinkRoundTripsToStorageKey(t *testing.T) {
	ctx := map[string]interface{}{
		"app_name": "MyApp",
		"version":  "1.0.0",
		"channel":  "nightly",
		"platform": "darwin",
		"arch":     "arm64",
		"api_url":  "https://api.example.com",
	}

	for _, updaterType := range []string{"default", "electron-builder", "squirrel_windows", "velopack", "sparkle"} {
		t.Run(updaterType, func(t *testing.T) {
			link, s3Key := updaters.BuildS3Key(ctx, "acme", "My App+1.0.0.dmg", "My App+1.0.0.dmg", updaterType)

			if got := PrivateObjectKey(link); got != s3Key {
				t.Errorf("PrivateObjectKey(%q) = %q, want %q", link, got, s3Key)
			}
			if _, err := url.Parse(link); err != nil {
				t.Errorf("link %q is not parseable: %v", link, err)
			}
		})
	}
}
