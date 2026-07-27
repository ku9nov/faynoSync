package info

import "testing"

func TestTupleFromContext(t *testing.T) {
	full := map[string]interface{}{"channel": "nightly", "platform": "macos", "arch": "arm64"}
	got := TupleFromContext(full)
	if len(got) != 1 || got[0] != (FeedTuple{"nightly", "macos", "arm64"}) {
		t.Fatalf("got %+v, want single nightly/macos/arm64 tuple", got)
	}

	// Any missing dimension -> nil so the caller falls back to a full regen
	// rather than regenerating nothing.
	for _, m := range []map[string]interface{}{
		{"platform": "macos", "arch": "arm64"},
		{"channel": "nightly", "arch": "arm64"},
		{"channel": "nightly", "platform": "macos"},
		{"channel": "nightly", "platform": "macos", "arch": ""},
		{},
	} {
		if got := TupleFromContext(m); got != nil {
			t.Errorf("TupleFromContext(%v) = %+v, want nil", m, got)
		}
	}
}

func TestSparkleKeysFromTuples(t *testing.T) {
	tuples := []FeedTuple{
		{"nightly", "macos", "arm64"},
		{"nightly", "macos", "arm64"}, // duplicate collapsed
		{"stable", "macos", "arm64"},
		{"", "macos", "arm64"},   // incomplete dropped
		{"nightly", "", "arm64"}, // incomplete dropped
	}
	keys := sparkleKeysFromTuples(tuples)
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2 (dedup + drop incomplete): %+v", len(keys), keys)
	}
	seen := map[sparkleFeedKey]bool{}
	for _, k := range keys {
		seen[k] = true
	}
	if !seen[(sparkleFeedKey{"nightly", "macos", "arm64"})] || !seen[(sparkleFeedKey{"stable", "macos", "arm64"})] {
		t.Errorf("unexpected keys: %+v", keys)
	}
}

func TestVelopackKeysFromTuples(t *testing.T) {
	tuples := []FeedTuple{
		{"nightly", "windows", "x64"},
		{"nightly", "windows", "x64"},
		{"nightly", "macos", "arm64"},
		{"nightly", "windows", ""},
	}
	keys := velopackKeysFromTuples(tuples)
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2: %+v", len(keys), keys)
	}
}

func TestKeysFromTuplesEmpty(t *testing.T) {
	if k := sparkleKeysFromTuples(nil); k != nil {
		t.Errorf("sparkleKeysFromTuples(nil) = %+v, want nil", k)
	}
	if k := velopackKeysFromTuples([]FeedTuple{{"", "", ""}}); k != nil {
		t.Errorf("velopackKeysFromTuples(incomplete) = %+v, want nil", k)
	}
}
