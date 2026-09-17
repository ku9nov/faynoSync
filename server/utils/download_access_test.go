package utils

import (
	"net/url"
	"testing"

	"github.com/spf13/viper"
)

func TestPrivateObjectKey(t *testing.T) {
	key := "MyApp-acme/nightly/darwin/arm64/My App+1.0.0.dmg"
	cases := map[string]struct {
		link string
		want string
	}{
		"private link":            {"https://api.example.com/download?key=" + url.QueryEscape(key), key},
		"link from older API_URL": {"http://old-host:9000/download?key=" + url.QueryEscape(key), key},
		"public link":             {"https://cdn.example.com/public/MyApp-acme/nightly/app.dmg", ""},
		"broken encoding":         {"https://api.example.com/download?key=%zz", ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := PrivateObjectKey(tc.link); got != tc.want {
				t.Fatalf("PrivateObjectKey(%q) = %q, want %q", tc.link, got, tc.want)
			}
		})
	}
}

func TestDefaultDownloadMode(t *testing.T) {
	env := viper.New()
	if got := DefaultDownloadMode(env); got != DownloadModeStrict {
		t.Fatalf("unset flag: got %q, want %q", got, DownloadModeStrict)
	}
	env.Set("ENABLE_PRIVATE_APP_DOWNLOADING", "true")
	if got := DefaultDownloadMode(env); got != DownloadModeUnlisted {
		t.Fatalf("flag true: got %q, want %q", got, DownloadModeUnlisted)
	}
}

func TestValidateDownloadMode(t *testing.T) {
	for _, mode := range []string{DownloadModeUnlisted, DownloadModeStrict} {
		if err := ValidateDownloadMode(mode); err != nil {
			t.Fatalf("%q rejected: %v", mode, err)
		}
	}
	for _, mode := range []string{"", "public", "STRICT"} {
		if err := ValidateDownloadMode(mode); err == nil {
			t.Fatalf("%q accepted", mode)
		}
	}
}
