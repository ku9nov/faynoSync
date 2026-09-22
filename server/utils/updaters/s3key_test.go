package updaters

import (
	"net/url"
	"testing"
)

func keyCtx(channel, platform, arch string) map[string]interface{} {
	return map[string]interface{}{
		"app_name": "MyApp",
		"version":  "1.0.0",
		"channel":  channel,
		"platform": platform,
		"arch":     arch,
		"api_url":  "https://api.example.com",
	}
}

// Characterization of the key layout every non-feed updater produces. These keys are
// persisted in artifact links, so a change here silently orphans already uploaded files.
func TestBuildS3KeyLayout(t *testing.T) {
	cases := []struct {
		name        string
		updaterType string
		ctx         map[string]interface{}
		newFileName string
		oldFileName string
		want        string
	}{
		{
			name:        "default full tuple",
			updaterType: "default",
			ctx:         keyCtx("nightly", "darwin", "arm64"),
			newFileName: "MyApp-1.0.0.dmg",
			oldFileName: "build.dmg",
			want:        "MyApp-acme/nightly/darwin/arm64/MyApp-1.0.0.dmg",
		},
		{
			name:        "default without channel platform arch",
			updaterType: "default",
			ctx:         keyCtx("", "", ""),
			newFileName: "MyApp-1.0.0.dmg",
			oldFileName: "build.dmg",
			want:        "MyApp-acme/MyApp-1.0.0.dmg",
		},
		{
			name:        "default channel only",
			updaterType: "default",
			ctx:         keyCtx("nightly", "", ""),
			newFileName: "MyApp-1.0.0.dmg",
			oldFileName: "build.dmg",
			want:        "MyApp-acme/nightly/MyApp-1.0.0.dmg",
		},
		{
			name:        "default platform and arch without channel",
			updaterType: "default",
			ctx:         keyCtx("", "darwin", "arm64"),
			newFileName: "MyApp-1.0.0.dmg",
			oldFileName: "build.dmg",
			want:        "MyApp-acme/darwin/arm64/MyApp-1.0.0.dmg",
		},
		{
			name:        "unknown updater falls through to default",
			updaterType: "manual",
			ctx:         keyCtx("nightly", "darwin", "arm64"),
			newFileName: "MyApp-1.0.0.dmg",
			oldFileName: "build.dmg",
			want:        "MyApp-acme/nightly/darwin/arm64/MyApp-1.0.0.dmg",
		},
		{
			name:        "tauri falls through to default",
			updaterType: "tauri",
			ctx:         keyCtx("nightly", "darwin", "arm64"),
			newFileName: "MyApp-1.0.0.tar.gz",
			oldFileName: "build.tar.gz",
			want:        "MyApp-acme/nightly/darwin/arm64/MyApp-1.0.0.tar.gz",
		},
		{
			name:        "electron-builder keeps the uploaded file name",
			updaterType: "electron-builder",
			ctx:         keyCtx("nightly", "darwin", "arm64"),
			newFileName: "MyApp-1.0.0.yml",
			oldFileName: "latest-mac.yml",
			want:        "electron-builder/MyApp-acme/1.0.0/nightly/darwin/arm64/latest-mac.yml",
		},
		{
			name:        "electron-builder without channel platform arch",
			updaterType: "electron-builder",
			ctx:         keyCtx("", "", ""),
			newFileName: "MyApp-1.0.0.yml",
			oldFileName: "latest-mac.yml",
			want:        "electron-builder/MyApp-acme/1.0.0/latest-mac.yml",
		},
		{
			name:        "squirrel_windows keeps the uploaded file name",
			updaterType: "squirrel_windows",
			ctx:         keyCtx("stable", "windows", "amd64"),
			newFileName: "MyApp-1.0.0",
			oldFileName: "RELEASES",
			want:        "squirrel_windows/MyApp-acme/1.0.0/stable/windows/amd64/RELEASES",
		},
		{
			name:        "squirrel_darwin falls through to default",
			updaterType: "squirrel_darwin",
			ctx:         keyCtx("stable", "darwin", "amd64"),
			newFileName: "MyApp-1.0.0.zip",
			oldFileName: "MyApp.zip",
			want:        "MyApp-acme/stable/darwin/amd64/MyApp-1.0.0.zip",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			link, s3Key := BuildS3Key(tc.ctx, "acme", tc.newFileName, tc.oldFileName, tc.updaterType)
			if s3Key != tc.want {
				t.Errorf("s3Key = %q, want %q", s3Key, tc.want)
			}
			wantLink := "https://api.example.com/download?key=" + url.QueryEscape(tc.want)
			if link != wantLink {
				t.Errorf("link = %q, want %q", link, wantLink)
			}
		})
	}
}

// The key must stay raw while the link carries it query-escaped, otherwise /download
// resolves a different object than the one that was uploaded.
func TestBuildS3KeyEscapesLinkNotKey(t *testing.T) {
	ctx := keyCtx("nightly", "darwin", "arm64")

	link, s3Key := BuildS3Key(ctx, "acme", "My App+1.0.0.dmg", "raw.dmg", "default")

	wantKey := "MyApp-acme/nightly/darwin/arm64/My App+1.0.0.dmg"
	if s3Key != wantKey {
		t.Errorf("s3Key = %q, want %q", s3Key, wantKey)
	}
	if link != "https://api.example.com/download?key="+url.QueryEscape(wantKey) {
		t.Errorf("link = %q does not carry the escaped key", link)
	}
}

// BuildS3Key reads api_url off the context map; upload sets it right before calling.
// Losing that assignment turns every key build into a panic.
func TestBuildS3KeyPanicsWithoutAPIURL(t *testing.T) {
	for _, updaterType := range []string{"default", "electron-builder", "squirrel_windows"} {
		t.Run(updaterType, func(t *testing.T) {
			ctx := keyCtx("nightly", "darwin", "arm64")
			delete(ctx, "api_url")

			defer func() {
				if recover() == nil {
					t.Errorf("BuildS3Key(%s) without api_url did not panic", updaterType)
				}
			}()
			BuildS3Key(ctx, "acme", "MyApp-1.0.0.dmg", "build.dmg", updaterType)
		})
	}
}
