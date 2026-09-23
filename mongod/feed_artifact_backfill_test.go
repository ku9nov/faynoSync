package mongod

import (
	"regexp"
	"testing"

	"github.com/spf13/viper"
)

func TestUpdaterFromObjectKey(t *testing.T) {
	cases := map[string]string{
		"velopack/admin/HelloVelopack/darwin/arm64/releases.nightly.json":  "velopack",
		"sparkle/admin/MyApp/darwin/arm64/appcast.xml":                     "sparkle",
		"squirrel_windows/MyApp-admin/1.2.3/stable/win32/amd64/RELEASES":   "squirrel_windows",
		"electron-builder/MyApp-admin/1.2.3/stable/win32/amd64/latest.yml": "electron-builder",
		"MyApp-admin/stable/darwin/arm64/MyApp.dmg":                        "",
		"": "",
	}
	for key, want := range cases {
		if got := updaterFromObjectKey(key); got != want {
			t.Errorf("updaterFromObjectKey(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestLinkIsFeed(t *testing.T) {
	env := viper.New()
	env.Set("API_URL", "http://localhost:9000")
	env.Set("S3_ENDPOINT", "http://s3.local")
	env.Set("S3_BUCKET_NAME", "faynosync")

	cases := []struct {
		link string
		want bool
	}{
		{"http://s3.local/faynosync/velopack/admin/App/darwin/arm64/releases.nightly.json", true},
		{"http://s3.local/faynosync/velopack/admin/App/darwin/arm64/App-1.2.3-full.nupkg", false},
		{"http://s3.local/faynosync/sparkle/admin/App/darwin/arm64/appcast.nightly.xml", true},
		{"http://s3.local/faynosync/sparkle/admin/App/darwin/arm64/App-1.2.3.dmg", false},
		{"http://s3.local/faynosync/electron-builder/App-admin/1.2.3/stable/win32/amd64/latest.yml", true},
		{"http://s3.local/faynosync/electron-builder/App-admin/1.2.3/stable/win32/amd64/App.exe.blockmap", false},
		{"http://localhost:9000/download?key=squirrel_windows%2FApp-admin%2F1.2.3%2Fstable%2Fwin32%2Famd64%2FRELEASES", true},
		{"http://localhost:9000/download?key=squirrel_windows%2FApp-admin%2F1.2.3%2Fstable%2Fwin32%2Famd64%2FApp-full.nupkg", false},
		// Default layout (manual/tauri/squirrel_darwin): no updater prefix, so never a feed
		// even when the file is named like one.
		{"http://s3.local/faynosync/App-admin/stable/linux/amd64/latest.yml", false},
	}
	for _, tc := range cases {
		if got := linkIsFeed(tc.link, env); got != tc.want {
			t.Errorf("linkIsFeed(%q) = %v, want %v", tc.link, got, tc.want)
		}
	}
}

// The prefilter must not drop anything linkIsFeed would mark; over-matching is fine.
func TestFeedLinkCandidateCoversEveryFeedShape(t *testing.T) {
	re := regexp.MustCompile(feedLinkCandidate)
	for _, link := range []string{
		"http://s3.local/b/velopack/admin/App/darwin/arm64/releases.nightly.json",
		"http://s3.local/b/sparkle/admin/App/darwin/arm64/appcast.xml",
		"http://s3.local/b/sparkle/admin/App/darwin/arm64/appcast.nightly.xml",
		"http://s3.local/b/electron-builder/App-admin/1.2.3/stable/win32/amd64/latest.yml",
		"http://s3.local/b/electron-builder/App-admin/1.2.3/stable/win32/amd64/latest-mac.yaml",
		"http://s3.local/b/squirrel_windows/App-admin/1.2.3/stable/win32/amd64/RELEASES",
		"http://localhost:9000/download?key=squirrel_windows%2FApp-admin%2FRELEASES",
	} {
		if !re.MatchString(link) {
			t.Errorf("prefilter missed feed link %q", link)
		}
	}
}
