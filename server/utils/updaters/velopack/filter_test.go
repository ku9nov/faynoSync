package velopack

import (
	"encoding/json"
	"testing"
)

func pubFull(version string) Release {
	return Release{
		Version:   version,
		Published: true,
		Full:      asset(version, "http://cdn/"+version+"-full.nupkg", 100),
		Delta:     asset(version, "http://cdn/"+version+"-delta.nupkg", 10),
	}
}

func versions(releases []Release) []string {
	out := make([]string, 0, len(releases))
	for _, r := range releases {
		out = append(out, r.Version)
	}
	return out
}

func TestCapAtVersionTrims(t *testing.T) {
	releases := []Release{pubFull("1.0.0"), pubFull("1.0.1"), pubFull("1.0.2"), pubFull("1.0.3")}

	capped := CapAtVersion(releases, "1.0.2", CompareVersions)
	got := versions(capped)
	if len(got) != 3 {
		t.Fatalf("expected 3 releases <= 1.0.2, got %v", got)
	}
	for _, v := range got {
		if CompareVersions(v, "1.0.2") > 0 {
			t.Errorf("version %s exceeds cap 1.0.2", v)
		}
	}
}

func TestCapAtVersionEmptyIsNoOp(t *testing.T) {
	releases := []Release{pubFull("1.0.0"), pubFull("1.0.1")}
	capped := CapAtVersion(releases, "", CompareVersions)
	if len(capped) != len(releases) {
		t.Fatalf("empty maxVersion must be a no-op, got %v", versions(capped))
	}
}

func TestBuildFeedAfterCapHighestFullIsIntermediate(t *testing.T) {
	releases := []Release{pubFull("1.0.0"), pubFull("1.0.1"), pubFull("1.0.2"), pubFull("1.0.3")}

	capped := CapAtVersion(releases, "1.0.2", CompareVersions)
	data, err := BuildFeed("HelloVelopack", capped)
	if err != nil {
		t.Fatalf("BuildFeed error: %v", err)
	}

	var doc feedDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid feed json: %v", err)
	}
	if len(doc.Assets) == 0 {
		t.Fatal("expected assets after cap")
	}

	// highest Full (first Full in descending output) must be the intermediate version
	for _, a := range doc.Assets {
		if a.Type == "Full" {
			if a.Version != "1.0.2" {
				t.Errorf("highest Full = %s, want intermediate 1.0.2", a.Version)
			}
			break
		}
	}

	// nothing above the intermediate may appear
	for _, a := range doc.Assets {
		if CompareVersions(a.Version, "1.0.2") > 0 {
			t.Errorf("asset %s %s exceeds intermediate cap", a.Version, a.Type)
		}
	}
}
