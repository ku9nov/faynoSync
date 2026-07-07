package velopack

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

type FeedAsset struct {
	PackageId     string `json:"PackageId"`
	Version       string `json:"Version"`
	Type          string `json:"Type"`
	FileName      string `json:"FileName"`
	SHA1          string `json:"SHA1"`
	SHA256        string `json:"SHA256"`
	Size          int64  `json:"Size"`
	NotesMarkdown string `json:"NotesMarkdown"`
	NotesHTML     string `json:"NotesHTML"`
}

type Release struct {
	Version       string
	Published     bool
	Intermediate  bool
	NotesMarkdown string
	Full          *FeedAsset
	Delta         *FeedAsset
}

type feedDocument struct {
	Assets []FeedAsset `json:"Assets"`
}

func BuildFeed(packageId string, releases []Release) ([]byte, error) {
	sorted := make([]Release, len(releases))
	copy(sorted, releases)
	sort.SliceStable(sorted, func(i, j int) bool {
		return CompareVersions(sorted[i].Version, sorted[j].Version) > 0
	})

	assets := make([]FeedAsset, 0, len(sorted))
	for i, r := range sorted {
		if !r.Published {
			continue
		}
		if r.Full != nil {
			full := *r.Full
			full.PackageId = packageId
			full.Version = r.Version
			full.Type = "Full"
			full.NotesMarkdown = r.NotesMarkdown
			full.NotesHTML = RenderNotesHTML(r.NotesMarkdown)
			assets = append(assets, full)
		}
		if r.Delta != nil && deltaBaseAvailable(sorted, i) {
			delta := *r.Delta
			delta.PackageId = packageId
			delta.Version = r.Version
			delta.Type = "Delta"
			assets = append(assets, delta)
		}
	}

	// Disable HTML escaping so NotesHTML renders as literal <tags> in the feed
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(feedDocument{Assets: assets}); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func deltaBaseAvailable(sorted []Release, i int) bool {
	for j := i + 1; j < len(sorted); j++ {
		if CompareVersions(sorted[j].Version, sorted[i].Version) < 0 {
			return sorted[j].Published && sorted[j].Full != nil
		}
	}
	return false
}

func CompareVersions(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	n := len(aParts)
	if len(bParts) > n {
		n = len(bParts)
	}

	for i := 0; i < n; i++ {
		av := versionComponent(aParts, i)
		bv := versionComponent(bParts, i)
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

func versionComponent(parts []string, i int) int {
	if i >= len(parts) {
		return 0
	}
	v, err := strconv.Atoi(strings.TrimSpace(parts[i]))
	if err != nil {
		return 0
	}
	return v
}
