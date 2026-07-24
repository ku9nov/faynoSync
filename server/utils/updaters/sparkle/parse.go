package sparkle

import (
	"bytes"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/beevik/etree"
)

// ParseAppcast parses a Sparkle appcast and returns metadata keyed by the
// enclosure url basename. Each <item> is preserved verbatim (RawItem) on its full
// enclosure's meta so materialization can re-emit every element — including ones
// faynoSync doesn't model. Delta enclosures yield lightweight metas used only to
// match their url to a stored artifact link. Unknown elements/namespaces survive
// because etree round-trips them faithfully (encoding/xml would drop them).
func ParseAppcast(content []byte) (map[string]SparkleMeta, error) {
	if len(bytes.TrimSpace(content)) == 0 {
		return nil, fmt.Errorf("sparkle appcast is empty")
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(content); err != nil {
		return nil, fmt.Errorf("invalid sparkle appcast: %w", err)
	}

	result := make(map[string]SparkleMeta)
	for _, item := range doc.FindElements("//item") {
		fullEnc := item.SelectElement("enclosure")
		if fullEnc == nil {
			continue
		}
		fullName := enclosureBasename(fullEnc.SelectAttrValue("url", ""))
		if fullName == "" {
			continue
		}

		raw, err := serializeElement(item)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize sparkle item: %w", err)
		}
		result[fullName] = SparkleMeta{
			FileName:       fullName,
			Kind:           KindFull,
			SparkleVersion: itemSparkleVersion(item),
			RawItem:        raw,
		}

		if deltas := item.SelectElement("sparkle:deltas"); deltas != nil {
			for _, d := range deltas.SelectElements("enclosure") {
				dName := enclosureBasename(d.SelectAttrValue("url", ""))
				if dName == "" {
					continue
				}
				result[dName] = SparkleMeta{FileName: dName, Kind: KindDelta}
			}
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("sparkle appcast has no items with enclosures")
	}

	return result, nil
}

func itemSparkleVersion(item *etree.Element) string {
	if v := item.SelectElement("sparkle:version"); v != nil {
		return strings.TrimSpace(v.Text())
	}
	return ""
}

func serializeElement(el *etree.Element) (string, error) {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	return doc.WriteToString()
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
