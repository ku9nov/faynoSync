package sparkle

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/url"
	"path"
	"strings"
)

type rawEnclosure struct {
	URL                     string `xml:"url,attr"`
	Length                  int64  `xml:"length,attr"`
	Type                    string `xml:"type,attr"`
	EdSignature             string `xml:"edSignature,attr"`
	DeltaFrom               string `xml:"deltaFrom,attr"`
	DeltaFromExecutableSize string `xml:"deltaFromSparkleExecutableSize,attr"`
	DeltaFromLocales        string `xml:"deltaFromSparkleLocales,attr"`
}

// sparkleVersionElem accepts sparkle:version in either child-element form
// (<sparkle:version>2</sparkle:version>) or attribute form on the enclosure.
type appcastItem struct {
	Title                 string       `xml:"title"`
	SparkleVersion        string       `xml:"version"`
	ShortVersionString    string       `xml:"shortVersionString"`
	MinimumSystemVersion  string       `xml:"minimumSystemVersion"`
	PhasedRolloutInterval string       `xml:"phasedRolloutInterval"`
	Enclosure             rawEnclosure `xml:"enclosure"`
	Deltas                struct {
		Enclosures []rawEnclosure `xml:"enclosure"`
	} `xml:"deltas"`
}

type appcastFeed struct {
	Items []appcastItem `xml:"channel>item"`
}

// ParseAppcast parses a Sparkle appcast and returns metadata keyed by the
// enclosure url basename. Each <item> yields one full SparkleMeta plus one delta
// SparkleMeta per nested <sparkle:deltas>/<enclosure>. Item-level fields
// (sparkle:version, shortVersionString, minimumSystemVersion, phasedRolloutInterval)
// attach to the full meta; edSignature/length are read off each enclosure.
func ParseAppcast(content []byte) (map[string]SparkleMeta, error) {
	if len(bytes.TrimSpace(content)) == 0 {
		return nil, fmt.Errorf("sparkle appcast is empty")
	}

	var feed appcastFeed
	if err := xml.Unmarshal(content, &feed); err != nil {
		return nil, fmt.Errorf("invalid sparkle appcast: %w", err)
	}

	result := make(map[string]SparkleMeta)
	for _, it := range feed.Items {
		if fullName := enclosureBasename(it.Enclosure.URL); fullName != "" {
			result[fullName] = SparkleMeta{
				FileName:              fullName,
				Kind:                  KindFull,
				EdSignature:           it.Enclosure.EdSignature,
				Length:                it.Enclosure.Length,
				Type:                  it.Enclosure.Type,
				SparkleVersion:        it.SparkleVersion,
				ShortVersionString:    it.ShortVersionString,
				MinimumSystemVersion:  it.MinimumSystemVersion,
				PhasedRolloutInterval: it.PhasedRolloutInterval,
			}
		}
		for _, d := range it.Deltas.Enclosures {
			dName := enclosureBasename(d.URL)
			if dName == "" {
				continue
			}
			result[dName] = SparkleMeta{
				FileName:                dName,
				Kind:                    KindDelta,
				EdSignature:             d.EdSignature,
				Length:                  d.Length,
				Type:                    d.Type,
				DeltaFrom:               d.DeltaFrom,
				DeltaFromExecutableSize: d.DeltaFromExecutableSize,
				DeltaFromLocales:        d.DeltaFromLocales,
			}
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("sparkle appcast has no items with enclosures")
	}

	return result, nil
}

// enclosureBasename returns the decoded file name of an enclosure url so it can
// be matched against an uploaded multipart file name (e.g. "MyApp%201.1.zip" ->
// "MyApp 1.1.zip").
func enclosureBasename(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	if u, err := url.Parse(rawURL); err == nil && u.Path != "" {
		return path.Base(u.Path)
	}
	name := rawURL
	if i := strings.LastIndexAny(name, "/\\"); i >= 0 {
		name = name[i+1:]
	}
	if decoded, err := url.PathUnescape(name); err == nil {
		return decoded
	}
	return name
}
