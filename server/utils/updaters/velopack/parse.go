package velopack

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type feedAsset struct {
	Type     string
	FileName string
	SHA1     string
	SHA256   string
	Size     int64
}

type feed struct {
	Assets []feedAsset
}

// ParseFeed parses a releases.{channel}.json produced by vpk and returns a map
// keyed by FileName, holding only Full/Delta assets. Hashes and size are taken
// verbatim; Installer/Portable entries are ignored (they never enter the feed).
func ParseFeed(content []byte) (map[string]VelopackMeta, error) {
	if len(bytes.TrimSpace(content)) == 0 {
		return nil, fmt.Errorf("velopack releases feed is empty")
	}

	var f feed
	if err := json.Unmarshal(content, &f); err != nil {
		return nil, fmt.Errorf("invalid velopack releases feed: %w", err)
	}

	result := make(map[string]VelopackMeta)
	for _, a := range f.Assets {
		if a.Type != "Full" && a.Type != "Delta" {
			continue
		}
		if a.FileName == "" {
			continue
		}
		result[a.FileName] = VelopackMeta{
			Type:     a.Type,
			FileName: a.FileName,
			SHA1:     a.SHA1,
			SHA256:   a.SHA256,
			Size:     a.Size,
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("velopack releases feed has no Full or Delta assets")
	}

	return result, nil
}
