package info

import (
	"path"
	"testing"
)

func TestCreateCacheKeyIsScopedByOwner(t *testing.T) {
	params := map[string]interface{}{"owner": "alice", "app_name": "myapp", "version": "1.0.0", "channel": "stable", "platform": "darwin", "arch": "arm64"}
	other := map[string]interface{}{"owner": "bob", "app_name": "myapp", "version": "1.0.0", "channel": "stable", "platform": "darwin", "arch": "arm64"}
	if CreateCacheKey(params) == CreateCacheKey(other) {
		t.Fatalf("owners share a cache key: %s", CreateCacheKey(params))
	}
}

func TestCreateCacheKeyCannotBeForgedThroughOwner(t *testing.T) {
	victim := map[string]interface{}{"owner": "alice", "app_name": "myapp", "version": "1.0.0", "channel": "stable", "platform": "darwin", "arch": "arm64", "updater": "tauri"}
	forged := map[string]interface{}{"owner": "alice&app_name=myapp&version=1.0.0&channel=stable&platform=darwin&arch=arm64&updater=tauri", "app_name": "", "version": "", "channel": "", "platform": "", "arch": ""}
	if CreateCacheKey(victim) == CreateCacheKey(forged) {
		t.Fatal("a crafted owner produced another tenant's cache key")
	}
}

// Redis glob and path.Match agree here because escaped values contain no '/'.
func TestCacheKeyPatternMatchesOnlyOwnAppChannel(t *testing.T) {
	pattern := CacheKeyPattern("alice", "my app", "stable")
	cases := map[string]struct {
		params map[string]interface{}
		want   bool
	}{
		"checkVersion":                {map[string]interface{}{"owner": "alice", "app_name": "my app", "version": "1.2.3", "channel": "stable", "platform": "windows", "arch": "amd64", "updater": "squirrel_windows"}, true},
		"apps/latest without version": {map[string]interface{}{"owner": "alice", "app_name": "my app", "channel": "stable", "platform": "", "arch": "", "package": "dmg"}, true},
		"other owner":                 {map[string]interface{}{"owner": "bob", "app_name": "my app", "version": "1.2.3", "channel": "stable", "platform": "windows", "arch": "amd64"}, false},
		"other channel":               {map[string]interface{}{"owner": "alice", "app_name": "my app", "version": "1.2.3", "channel": "beta", "platform": "windows", "arch": "amd64"}, false},
		"other app":                   {map[string]interface{}{"owner": "alice", "app_name": "my app2", "version": "1.2.3", "channel": "stable", "platform": "windows", "arch": "amd64"}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			key := CreateCacheKey(tc.params)
			matched, err := path.Match(pattern, key)
			if err != nil {
				t.Fatal(err)
			}
			if matched != tc.want {
				t.Fatalf("pattern %q vs key %q: matched=%v, want %v", pattern, key, matched, tc.want)
			}
		})
	}

	if _, err := path.Match(CacheKeyPattern("a*[", "b?", "c"), "x"); err != nil {
		t.Fatalf("glob characters in names must be escaped: %v", err)
	}
}
