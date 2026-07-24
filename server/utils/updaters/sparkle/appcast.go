package sparkle

import (
	"bytes"
	"encoding/xml"
	"sort"

	"faynoSync/server/utils/updaters/velopack"
)

const (
	sparkleNamespace     = "http://www.andymatuschak.org/xml-namespaces/sparkle"
	defaultEnclosureType = "application/octet-stream"
	xmlDeclaration       = `<?xml version="1.0" encoding="UTF-8"?>` + "\n"
)

// Asset pairs a stored SparkleMeta with the faynoSync artifact link that
// replaces the uploaded appcast's original enclosure url. edSignature signs the
// archive bytes, not the xml, so rewriting the url keeps the signature valid.
type Asset struct {
	Meta SparkleMeta
	Link string
}

// Release is one version's Sparkle content: a required full archive plus any
// deltas, overlaid with faynoSync-managed fields (published/critical/changelog).
type Release struct {
	Version       string
	Published     bool
	Critical      bool
	NotesMarkdown string
	PubDate       string
	Full          *Asset
	Deltas        []Asset
}

type xmlRSS struct {
	XMLName xml.Name   `xml:"rss"`
	Sparkle string     `xml:"xmlns:sparkle,attr"`
	Version string     `xml:"version,attr"`
	Channel xmlChannel `xml:"channel"`
}

type xmlChannel struct {
	Title string    `xml:"title"`
	Items []xmlItem `xml:"item"`
}

type xmlItem struct {
	Title                 string       `xml:"title"`
	PubDate               string       `xml:"pubDate,omitempty"`
	Critical              *struct{}    `xml:"sparkle:criticalUpdate"`
	PhasedRolloutInterval string       `xml:"sparkle:phasedRolloutInterval,omitempty"`
	SparkleVersion        string       `xml:"sparkle:version,omitempty"`
	ShortVersionString    string       `xml:"sparkle:shortVersionString,omitempty"`
	MinimumSystemVersion  string       `xml:"sparkle:minimumSystemVersion,omitempty"`
	Description           *xmlCDATA    `xml:"description,omitempty"`
	Enclosure             xmlEnclosure `xml:"enclosure"`
	Deltas                *xmlDeltas   `xml:"sparkle:deltas,omitempty"`
}

type xmlCDATA struct {
	Value string `xml:",cdata"`
}

type xmlEnclosure struct {
	XMLName                 xml.Name `xml:"enclosure"`
	URL                     string   `xml:"url,attr"`
	Length                  int64    `xml:"length,attr"`
	Type                    string   `xml:"type,attr"`
	EdSignature             string   `xml:"sparkle:edSignature,attr,omitempty"`
	DeltaFrom               string   `xml:"sparkle:deltaFrom,attr,omitempty"`
	DeltaFromExecutableSize string   `xml:"sparkle:deltaFromSparkleExecutableSize,attr,omitempty"`
	DeltaFromLocales        string   `xml:"sparkle:deltaFromSparkleLocales,attr,omitempty"`
}

type xmlDeltas struct {
	Enclosures []xmlEnclosure `xml:"enclosure"`
}

// BuildAppcast materializes an RSS 2.0 + Sparkle appcast: one <item> per
// published release, newest first. Managed fields (publish/critical/changelog)
// override the uploaded appcast; everything Sparkle-specific (edSignature,
// sparkle:version, deltas, ...) is passed through verbatim from stored metadata.
func BuildAppcast(appTitle string, releases []Release) ([]byte, error) {
	sorted := make([]Release, len(releases))
	copy(sorted, releases)
	sort.SliceStable(sorted, func(i, j int) bool {
		return velopack.CompareVersions(sorted[i].Version, sorted[j].Version) > 0
	})

	items := make([]xmlItem, 0, len(sorted))
	for _, r := range sorted {
		if !r.Published || r.Full == nil {
			continue
		}

		full := r.Full.Meta
		item := xmlItem{
			Title:                 itemTitle(full, r.Version),
			PubDate:               r.PubDate,
			PhasedRolloutInterval: full.PhasedRolloutInterval,
			SparkleVersion:        full.SparkleVersion,
			ShortVersionString:    full.ShortVersionString,
			MinimumSystemVersion:  full.MinimumSystemVersion,
			Enclosure: xmlEnclosure{
				URL:         r.Full.Link,
				Length:      full.Length,
				Type:        enclosureType(full.Type),
				EdSignature: full.EdSignature,
			},
		}
		if r.Critical {
			item.Critical = &struct{}{}
		}
		if html := velopack.RenderNotesHTML(r.NotesMarkdown); html != "" {
			item.Description = &xmlCDATA{Value: html}
		}
		if deltas := buildDeltas(r.Deltas); deltas != nil {
			item.Deltas = deltas
		}

		items = append(items, item)
	}

	feed := xmlRSS{
		Sparkle: sparkleNamespace,
		Version: "2.0",
		Channel: xmlChannel{Title: appTitle, Items: items},
	}

	body, err := xml.MarshalIndent(feed, "", "    ")
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.WriteString(xmlDeclaration)
	buf.Write(body)
	return buf.Bytes(), nil
}

func buildDeltas(deltas []Asset) *xmlDeltas {
	if len(deltas) == 0 {
		return nil
	}
	enclosures := make([]xmlEnclosure, 0, len(deltas))
	for _, d := range deltas {
		enclosures = append(enclosures, xmlEnclosure{
			URL:                     d.Link,
			Length:                  d.Meta.Length,
			Type:                    enclosureType(d.Meta.Type),
			EdSignature:             d.Meta.EdSignature,
			DeltaFrom:               d.Meta.DeltaFrom,
			DeltaFromExecutableSize: d.Meta.DeltaFromExecutableSize,
			DeltaFromLocales:        d.Meta.DeltaFromLocales,
		})
	}
	return &xmlDeltas{Enclosures: enclosures}
}

func itemTitle(full SparkleMeta, version string) string {
	if full.ShortVersionString != "" {
		return full.ShortVersionString
	}
	return version
}

func enclosureType(t string) string {
	if t == "" {
		return defaultEnclosureType
	}
	return t
}
