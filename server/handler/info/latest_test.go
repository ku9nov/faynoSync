package info

import (
	"encoding/json"
	"testing"
)

// resolveCachedHasUpdate must survive the Redis JSON round-trip. A raw string
// body (squirrel_windows RELEASES feed) has no update_available field, so the
// persisted HasUpdate flag is the only source of truth; a map body keeps
// carrying it inline and takes precedence.
func TestResolveCachedHasUpdate(t *testing.T) {
	cases := []struct {
		name   string
		cached CachedResponse
		want   bool
	}{
		{
			name:   "string feed outdated uses persisted flag",
			cached: CachedResponse{Response: "37BDE1F0 pkg-full.nupkg 100", ContentType: squirrelReleasesContentType, HasUpdate: true},
			want:   true,
		},
		{
			name:   "string feed latest uses persisted flag",
			cached: CachedResponse{Response: "37BDE1F0 pkg-full.nupkg 100", ContentType: squirrelReleasesContentType, HasUpdate: false},
			want:   false,
		},
		{
			name:   "map body overrides flag with update_available true",
			cached: CachedResponse{Response: map[string]interface{}{"update_available": true}, HasUpdate: false},
			want:   true,
		},
		{
			name:   "map body overrides flag with update_available false",
			cached: CachedResponse{Response: map[string]interface{}{"update_available": false}, HasUpdate: true},
			want:   false,
		},
		{
			name:   "map body without update_available falls back to flag",
			cached: CachedResponse{Response: map[string]interface{}{"critical": true}, HasUpdate: true},
			want:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.cached)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var decoded CachedResponse
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got := resolveCachedHasUpdate(decoded); got != tc.want {
				t.Errorf("resolveCachedHasUpdate = %v, want %v", got, tc.want)
			}
		})
	}
}
