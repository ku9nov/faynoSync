package utils

import (
	"testing"

	"github.com/spf13/viper"
)

func placementEnv() *viper.Viper {
	env := viper.New()
	env.Set("API_URL", "https://api.example.com")
	env.Set("S3_BUCKET_NAME", "public-bucket")
	env.Set("S3_BUCKET_NAME_PRIVATE", "private-bucket")
	return env
}

func artifactCtx() map[string]interface{} {
	return map[string]interface{}{
		"app_name": "MyApp",
		"version":  "1.0.0",
		"channel":  "nightly",
		"platform": "darwin",
		"arch":     "arm64",
	}
}

func TestBuildObjectPlacementPrivateApp(t *testing.T) {
	got := BuildObjectPlacement(artifactCtx(), "acme", "build.dmg", placementEnv(), true)

	want := ObjectPlacement{
		Key:          "MyApp-acme/nightly/darwin/arm64/MyApp-1.0.0.dmg",
		Extension:    ".dmg",
		Bucket:       "private-bucket",
		Public:       false,
		ContentType:  "",
		DownloadLink: "https://api.example.com/download?key=MyApp-acme%2Fnightly%2Fdarwin%2Farm64%2FMyApp-1.0.0.dmg",
	}
	if got != want {
		t.Errorf("placement = %+v, want %+v", got, want)
	}
}

// checkAppVisibility reports that the app is private; a public app keeps its
// artifacts in the public bucket, where the link comes from the storage client.
func TestBuildObjectPlacementPublicApp(t *testing.T) {
	got := BuildObjectPlacement(artifactCtx(), "acme", "build.dmg", placementEnv(), false)

	if !got.Public {
		t.Error("public app placement is not public")
	}
	if got.Bucket != "public-bucket" {
		t.Errorf("bucket = %q, want public-bucket", got.Bucket)
	}
}

// A logo is public even for a private app, and is renamed rather than versioned.
func TestBuildObjectPlacementLogo(t *testing.T) {
	ctxQuery := map[string]interface{}{
		"app_name": "MyApp",
		"version":  "0.0.0",
		"type":     "logo",
		"channel":  "",
		"platform": "",
		"arch":     "",
	}

	got := BuildObjectPlacement(ctxQuery, "acme", "my-logo.png", placementEnv(), true)

	if got.Key != "MyApp-acme/MyApp-logo.png" {
		t.Errorf("key = %q, want MyApp-acme/MyApp-logo.png", got.Key)
	}
	if !got.Public || got.Bucket != "public-bucket" {
		t.Errorf("logo placement = %+v, want the public bucket", got)
	}
}

func TestBuildObjectPlacementFileNaming(t *testing.T) {
	cases := []struct {
		fileName      string
		wantExtension string
		wantKey       string
	}{
		{"build.dmg", ".dmg", "MyApp-acme/nightly/darwin/arm64/MyApp-1.0.0.dmg"},
		// Only the last dot counts, so a compound extension is truncated.
		{"build.tar.gz", ".gz", "MyApp-acme/nightly/darwin/arm64/MyApp-1.0.0.gz"},
		{"RELEASES", "", "MyApp-acme/nightly/darwin/arm64/MyApp-1.0.0"},
		{".dotfile", ".dotfile", "MyApp-acme/nightly/darwin/arm64/MyApp-1.0.0.dotfile"},
	}

	for _, tc := range cases {
		t.Run(tc.fileName, func(t *testing.T) {
			got := BuildObjectPlacement(artifactCtx(), "acme", tc.fileName, placementEnv(), true)
			if got.Extension != tc.wantExtension {
				t.Errorf("extension = %q, want %q", got.Extension, tc.wantExtension)
			}
			if got.Key != tc.wantKey {
				t.Errorf("key = %q, want %q", got.Key, tc.wantKey)
			}
		})
	}
}

// Feed-based updaters keep the uploaded file name, and the feed objects carry the
// Content-Type their clients parse by.
func TestBuildObjectPlacementUpdaterKeysAndContentTypes(t *testing.T) {
	cases := []struct {
		updater         string
		fileName        string
		wantKey         string
		wantContentType string
	}{
		{"electron-builder", "latest-mac.yml", "electron-builder/MyApp-acme/1.0.0/nightly/darwin/arm64/latest-mac.yml", "text/yaml"},
		{"squirrel_windows", "RELEASES", "squirrel_windows/MyApp-acme/1.0.0/nightly/darwin/arm64/RELEASES", "text/plain"},
		{"velopack", "releases.nightly.json", "velopack/acme/MyApp/darwin/arm64/releases.nightly.json", "application/json"},
		{"sparkle", "MyApp-1.0.0.zip", "sparkle/acme/MyApp/darwin/arm64/MyApp-1.0.0.zip", ""},
	}

	for _, tc := range cases {
		t.Run(tc.updater, func(t *testing.T) {
			ctxQuery := artifactCtx()
			ctxQuery["updater"] = tc.updater

			got := BuildObjectPlacement(ctxQuery, "acme", tc.fileName, placementEnv(), true)
			if got.Key != tc.wantKey {
				t.Errorf("key = %q, want %q", got.Key, tc.wantKey)
			}
			if got.ContentType != tc.wantContentType {
				t.Errorf("contentType = %q, want %q", got.ContentType, tc.wantContentType)
			}
		})
	}
}

// BuildS3Key reads API_URL off the context map, so the placement has to put it there.
func TestBuildObjectPlacementSetsAPIURLOnContext(t *testing.T) {
	ctxQuery := artifactCtx()

	BuildObjectPlacement(ctxQuery, "acme", "build.dmg", placementEnv(), true)

	if ctxQuery["api_url"] != "https://api.example.com" {
		t.Errorf("ctxQuery[api_url] = %v, want the configured API_URL", ctxQuery["api_url"])
	}
}
