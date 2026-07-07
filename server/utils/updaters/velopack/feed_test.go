package velopack

import (
	"encoding/json"
	"strings"
	"testing"
)

func asset(version, fileName string, size int64) *FeedAsset {
	return &FeedAsset{
		Version:  version,
		FileName: fileName,
		SHA1:     "sha1-" + version,
		SHA256:   "sha256-" + version,
		Size:     size,
	}
}

func decodeFeed(t *testing.T, data []byte) feedDocument {
	t.Helper()
	var doc feedDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid feed json: %v", err)
	}
	return doc
}

func TestBuildFeedAllPublished(t *testing.T) {
	releases := []Release{
		{Version: "1.0.0", Published: true, Full: asset("1.0.0", "http://cdn/1.0.0-full.nupkg", 100), Delta: asset("1.0.0", "http://cdn/1.0.0-delta.nupkg", 10)},
		{Version: "1.0.1", Published: true, Full: asset("1.0.1", "http://cdn/1.0.1-full.nupkg", 101), Delta: asset("1.0.1", "http://cdn/1.0.1-delta.nupkg", 11)},
		{Version: "1.0.2", Published: true, Full: asset("1.0.2", "http://cdn/1.0.2-full.nupkg", 102), Delta: asset("1.0.2", "http://cdn/1.0.2-delta.nupkg", 12)},
	}

	data, err := BuildFeed("HelloVelopack", releases)
	if err != nil {
		t.Fatalf("BuildFeed error: %v", err)
	}
	doc := decodeFeed(t, data)

	// descending order: 1.0.2 Full, 1.0.2 Delta, 1.0.1 Full, 1.0.1 Delta, 1.0.0 Full
	want := []struct {
		version string
		typ     string
	}{
		{"1.0.2", "Full"},
		{"1.0.2", "Delta"},
		{"1.0.1", "Full"},
		{"1.0.1", "Delta"},
		{"1.0.0", "Full"},
	}
	if len(doc.Assets) != len(want) {
		t.Fatalf("got %d assets, want %d: %+v", len(doc.Assets), len(want), doc.Assets)
	}
	for i, w := range want {
		if doc.Assets[i].Version != w.version || doc.Assets[i].Type != w.typ {
			t.Errorf("asset[%d] = (%s,%s), want (%s,%s)", i, doc.Assets[i].Version, doc.Assets[i].Type, w.version, w.typ)
		}
		if doc.Assets[i].PackageId != "HelloVelopack" {
			t.Errorf("asset[%d] PackageId = %q, want HelloVelopack", i, doc.Assets[i].PackageId)
		}
	}

	// lowest version delta must be absent
	for _, a := range doc.Assets {
		if a.Version == "1.0.0" && a.Type == "Delta" {
			t.Error("lowest version delta must be excluded")
		}
	}
}

func TestBuildFeedFileNameIsBare(t *testing.T) {
	bareFull := "HelloVelopack-1.0.1-nightly-full.nupkg"
	bareDelta := "HelloVelopack-1.0.1-nightly-delta.nupkg"
	releases := []Release{
		{Version: "1.0.0", Published: true, Full: asset("1.0.0", "HelloVelopack-1.0.0-nightly-full.nupkg", 100)},
		{Version: "1.0.1", Published: true, Full: &FeedAsset{Version: "1.0.1", FileName: bareFull, SHA1: "a", SHA256: "b", Size: 1}, Delta: &FeedAsset{Version: "1.0.1", FileName: bareDelta, Size: 2}},
	}

	data, err := BuildFeed("HelloVelopack", releases)
	if err != nil {
		t.Fatalf("BuildFeed error: %v", err)
	}
	doc := decodeFeed(t, data)

	for _, a := range doc.Assets {
		if strings.Contains(a.FileName, "/") || strings.Contains(a.FileName, "http") {
			t.Errorf("FileName must be a bare name, got %q", a.FileName)
		}
	}

	found := false
	for _, a := range doc.Assets {
		if a.Version == "1.0.1" && a.Type == "Full" {
			if a.FileName != bareFull {
				t.Errorf("FileName = %q, want verbatim %q", a.FileName, bareFull)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("expected 1.0.1 Full asset")
	}
}

func TestBuildFeedUnpublishMiddle(t *testing.T) {
	releases := []Release{
		{Version: "1.0.0", Published: true, Full: asset("1.0.0", "http://cdn/1.0.0-full.nupkg", 100), Delta: asset("1.0.0", "http://cdn/1.0.0-delta.nupkg", 10)},
		{Version: "1.0.1", Published: false, Full: asset("1.0.1", "http://cdn/1.0.1-full.nupkg", 101), Delta: asset("1.0.1", "http://cdn/1.0.1-delta.nupkg", 11)},
		{Version: "1.0.2", Published: true, Full: asset("1.0.2", "http://cdn/1.0.2-full.nupkg", 102), Delta: asset("1.0.2", "http://cdn/1.0.2-delta.nupkg", 12)},
	}

	data, err := BuildFeed("HelloVelopack", releases)
	if err != nil {
		t.Fatalf("BuildFeed error: %v", err)
	}
	doc := decodeFeed(t, data)

	fullPresent := false
	for _, a := range doc.Assets {
		if a.Version == "1.0.1" {
			t.Errorf("unpublished version 1.0.1 must not appear: %+v", a)
		}
		if a.Version == "1.0.2" && a.Type == "Delta" {
			t.Error("1.0.2 delta must be dropped: its immediate base 1.0.1 is unpublished (hole)")
		}
		if a.Version == "1.0.2" && a.Type == "Full" {
			fullPresent = true
		}
	}
	if !fullPresent {
		t.Error("1.0.2 Full must remain as fallback")
	}
}

func TestBuildFeedDeltaHoleDropped(t *testing.T) {
	// 1.0.2 delta base is 1.0.1 (unpublished) -> hole -> drop 1.0.2 delta.
	releases := []Release{
		{Version: "1.0.0", Published: true, Full: asset("1.0.0", "http://cdn/1.0.0-full.nupkg", 100), Delta: asset("1.0.0", "http://cdn/1.0.0-delta.nupkg", 10)},
		{Version: "1.0.1", Published: false, Full: asset("1.0.1", "http://cdn/1.0.1-full.nupkg", 101), Delta: asset("1.0.1", "http://cdn/1.0.1-delta.nupkg", 11)},
		{Version: "1.0.2", Published: true, Full: asset("1.0.2", "http://cdn/1.0.2-full.nupkg", 102), Delta: asset("1.0.2", "http://cdn/1.0.2-delta.nupkg", 12)},
	}

	doc := decodeFeed(t, mustBuild(t, releases))
	for _, a := range doc.Assets {
		if a.Version == "1.0.2" && a.Type == "Delta" {
			t.Error("delta 1.0.2 must be dropped across the 1.0.1 hole")
		}
	}
}

func TestBuildFeedContiguousChainKeepsDeltas(t *testing.T) {
	releases := []Release{
		{Version: "1.0.0", Published: true, Full: asset("1.0.0", "http://cdn/1.0.0-full.nupkg", 100), Delta: asset("1.0.0", "http://cdn/1.0.0-delta.nupkg", 10)},
		{Version: "1.0.1", Published: true, Full: asset("1.0.1", "http://cdn/1.0.1-full.nupkg", 101), Delta: asset("1.0.1", "http://cdn/1.0.1-delta.nupkg", 11)},
		{Version: "1.0.2", Published: true, Full: asset("1.0.2", "http://cdn/1.0.2-full.nupkg", 102), Delta: asset("1.0.2", "http://cdn/1.0.2-delta.nupkg", 12)},
	}

	doc := decodeFeed(t, mustBuild(t, releases))

	deltas := map[string]bool{}
	for _, a := range doc.Assets {
		if a.Type == "Delta" {
			deltas[a.Version] = true
		}
	}
	if !deltas["1.0.1"] || !deltas["1.0.2"] {
		t.Errorf("contiguous chain must keep 1.0.1 and 1.0.2 deltas, got %v", deltas)
	}
	if deltas["1.0.0"] {
		t.Error("lowest version 1.0.0 delta must be dropped (no base)")
	}
}

func TestBuildFeedNoPublished(t *testing.T) {
	releases := []Release{
		{Version: "1.0.0", Published: false, Full: asset("1.0.0", "http://cdn/1.0.0-full.nupkg", 100)},
		{Version: "1.0.1", Published: false, Full: asset("1.0.1", "http://cdn/1.0.1-full.nupkg", 101)},
	}
	if got := string(mustBuild(t, releases)); got != `{"Assets":[]}` {
		t.Errorf("all-unpublished feed = %q, want {\"Assets\":[]}", got)
	}
}

func mustBuild(t *testing.T, releases []Release) []byte {
	t.Helper()
	data, err := BuildFeed("HelloVelopack", releases)
	if err != nil {
		t.Fatalf("BuildFeed error: %v", err)
	}
	return data
}

func TestBuildFeedEmpty(t *testing.T) {
	data, err := BuildFeed("HelloVelopack", nil)
	if err != nil {
		t.Fatalf("BuildFeed error: %v", err)
	}
	if string(data) != `{"Assets":[]}` {
		t.Errorf("empty feed = %q, want {\"Assets\":[]}", string(data))
	}
}

func TestFeedObjectKey(t *testing.T) {
	got := FeedObjectKey("acme", "HelloVelopack", "osx", "arm64", "stable")
	want := "velopack/acme/HelloVelopack/osx/arm64/releases.stable.json"
	if got != want {
		t.Errorf("FeedObjectKey = %q, want %q", got, want)
	}
}
