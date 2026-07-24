package velopack

import "testing"

func TestGetUpdaterType(t *testing.T) {
	if got := NewFileValidator(UpdaterType).GetUpdaterType(); got != UpdaterType {
		t.Errorf("GetUpdaterType = %q, want %q", got, UpdaterType)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"1.2.0", "1.10.0", -1}, // numeric, not lexical
		{"1.0", "1.0.0", 0},     // unequal length -> missing components are 0
		{"1.0.0", "1.0", 0},
		{"2.0", "1.9.9", 1},
		{" 1. 0. 1 ", "1.0.1", 0}, // whitespace trimmed
		{"1.0.x", "1.0.0", 0},     // non-numeric component -> 0
		{"1.0.1", "1.0.x", 1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestParseFeedSkipsEmptyFileName(t *testing.T) {
	content := []byte(`{"Assets":[
		{"Type":"Full","FileName":"","SHA1":"a","SHA256":"b","Size":1},
		{"Type":"Full","FileName":"app-full.nupkg","SHA1":"c","SHA256":"d","Size":2}
	]}`)
	meta, err := ParseFeed(content)
	if err != nil {
		t.Fatalf("ParseFeed error: %v", err)
	}
	if len(meta) != 1 {
		t.Fatalf("got %d entries, want 1 (empty FileName skipped)", len(meta))
	}
	if _, ok := meta["app-full.nupkg"]; !ok {
		t.Error("expected app-full.nupkg entry")
	}
}
