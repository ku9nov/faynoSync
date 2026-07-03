package velopack

import (
	"encoding/json"
	"mime/multipart"
	"os"
	"path/filepath"
	"testing"
)

func loadRealFeed(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join(os.Getenv("HOME"), "work-project", "faynosync-velopack-python-example", "releases", "releases.osx.json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("real releases.osx.json not available: %v", err)
	}
	return content
}

func TestParseFeedRealFile(t *testing.T) {
	content := loadRealFeed(t)

	meta, err := ParseFeed(content)
	if err != nil {
		t.Fatalf("ParseFeed error: %v", err)
	}

	// Derive expectations from the file itself so the test survives the example
	// feed being regenerated with different versions/hashes.
	var raw struct {
		Assets []struct {
			Type     string
			FileName string
			SHA1     string
			SHA256   string
			Size     int64
		}
	}
	if err := json.Unmarshal(content, &raw); err != nil {
		t.Fatalf("invalid real feed: %v", err)
	}

	hasFull, hasDelta := false, false
	for _, a := range raw.Assets {
		switch a.Type {
		case "Full", "Delta":
			m, ok := meta[a.FileName]
			if !ok {
				t.Fatalf("expected %s entry %q keyed by FileName", a.Type, a.FileName)
			}
			if m.Type != a.Type || m.SHA1 != a.SHA1 || m.SHA256 != a.SHA256 || m.Size != a.Size {
				t.Errorf("verbatim mismatch for %q: got %+v, want type=%s sha1=%s sha256=%s size=%d",
					a.FileName, m, a.Type, a.SHA1, a.SHA256, a.Size)
			}
			if a.Type == "Full" {
				hasFull = true
			} else {
				hasDelta = true
			}
		default:
			if _, ok := meta[a.FileName]; ok {
				t.Errorf("%s entry %q must be ignored", a.Type, a.FileName)
			}
		}
	}

	if !hasFull {
		t.Error("real feed expected to contain at least one Full asset")
	}
	if !hasDelta {
		t.Error("real feed expected to contain at least one Delta asset")
	}
	if len(meta) != countFullDelta(raw.Assets) {
		t.Errorf("map has %d entries, want %d Full/Delta", len(meta), countFullDelta(raw.Assets))
	}
}

func countFullDelta(assets []struct {
	Type     string
	FileName string
	SHA1     string
	SHA256   string
	Size     int64
}) int {
	n := 0
	for _, a := range assets {
		if a.Type == "Full" || a.Type == "Delta" {
			n++
		}
	}
	return n
}

func TestParseFeedIgnoresInstallerAndPortable(t *testing.T) {
	content := []byte(`{"Assets":[
		{"Type":"Full","FileName":"app-full.nupkg","SHA1":"a","SHA256":"b","Size":1},
		{"Type":"Delta","FileName":"app-delta.nupkg","SHA1":"c","SHA256":"d","Size":2},
		{"Type":"Installer","FileName":"Setup.exe","SHA1":"e","SHA256":"f","Size":3},
		{"Type":"Portable","FileName":"Portable.zip","SHA1":"g","SHA256":"h","Size":4}
	]}`)

	meta, err := ParseFeed(content)
	if err != nil {
		t.Fatalf("ParseFeed error: %v", err)
	}
	if len(meta) != 2 {
		t.Fatalf("expected 2 entries (Full+Delta), got %d", len(meta))
	}
	if _, ok := meta["Setup.exe"]; ok {
		t.Errorf("Installer must be ignored")
	}
	if _, ok := meta["Portable.zip"]; ok {
		t.Errorf("Portable must be ignored")
	}
}

func TestParseFeedEmptyOrInvalid(t *testing.T) {
	cases := map[string][]byte{
		"empty":          []byte(""),
		"whitespace":     []byte("   \n"),
		"malformed json": []byte(`{"Assets":[`),
		"no full/delta":  []byte(`{"Assets":[{"Type":"Installer","FileName":"Setup.exe"}]}`),
	}
	for name, content := range cases {
		if _, err := ParseFeed(content); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func fileHeaders(names ...string) []*multipart.FileHeader {
	headers := make([]*multipart.FileHeader, 0, len(names))
	for _, n := range names {
		headers = append(headers, &multipart.FileHeader{Filename: n})
	}
	return headers
}

func TestValidatorMissingFull(t *testing.T) {
	v := NewFileValidator(UpdaterType)
	err := v.Validate(fileHeaders("HelloVelopack-1.0.3-osx-delta.nupkg", "releases.osx.json"))
	if err == nil {
		t.Fatal("expected error when no *-full.nupkg present")
	}
}

func TestValidatorMissingReleases(t *testing.T) {
	v := NewFileValidator(UpdaterType)
	err := v.Validate(fileHeaders("HelloVelopack-1.0.3-osx-full.nupkg"))
	if err == nil {
		t.Fatal("expected error when no releases.*.json present")
	}
}

func TestValidatorOK(t *testing.T) {
	v := NewFileValidator(UpdaterType)
	err := v.Validate(fileHeaders("HelloVelopack-1.0.3-osx-full.nupkg", "HelloVelopack-1.0.3-osx-delta.nupkg", "releases.osx.json"))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestBuildS3Key(t *testing.T) {
	ctxQuery := map[string]interface{}{
		"app_name": "HelloVelopack",
		"version":  "1.0.3",
		"channel":  "stable",
		"platform": "osx",
		"arch":     "arm64",
		"api_url":  "http://api.local",
	}

	link, key := BuildS3Key(ctxQuery, "acme", "HelloVelopack-1.0.3-osx-full.nupkg")

	wantKey := "velopack/acme/HelloVelopack/osx/arm64/HelloVelopack-1.0.3-osx-full.nupkg"
	if key != wantKey {
		t.Errorf("s3Key = %q, want %q", key, wantKey)
	}
	if link == "" {
		t.Error("expected non-empty link")
	}
}
