package sparkle

import (
	"fmt"
	"sort"
	"strings"

	"faynoSync/server/utils/updaters/velopack"

	"github.com/beevik/etree"
)

const sparkleNamespace = "http://www.andymatuschak.org/xml-namespaces/sparkle"

type Asset struct {
	Meta SparkleMeta
	Link string
}

type Release struct {
	Version       string
	Published     bool
	Critical      bool
	NotesMarkdown string
	PubDate       string
	Full          *Asset
	Deltas        []Asset
}

// BuildAppcast materializes an RSS 2.0 + Sparkle appcast by re-emitting each published release's raw <item>
func BuildAppcast(appTitle string, releases []Release) ([]byte, error) {
	sorted := make([]Release, len(releases))
	copy(sorted, releases)
	sort.SliceStable(sorted, func(i, j int) bool {
		return velopack.CompareVersions(releaseSortKey(sorted[i]), releaseSortKey(sorted[j])) > 0
	})

	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	rss := doc.CreateElement("rss")
	rss.CreateAttr("xmlns:sparkle", sparkleNamespace)
	rss.CreateAttr("version", "2.0")
	channel := rss.CreateElement("channel")
	channel.CreateElement("title").SetText(appTitle)

	for _, r := range sorted {
		if !r.Published || r.Full == nil || strings.TrimSpace(r.Full.Meta.RawItem) == "" {
			continue
		}

		itemDoc := etree.NewDocument()
		if err := itemDoc.ReadFromString(r.Full.Meta.RawItem); err != nil {
			return nil, fmt.Errorf("failed to parse stored sparkle item for %s: %w", r.Version, err)
		}
		item := itemDoc.Root()
		if item == nil {
			continue
		}

		rewriteEnclosureURLs(item, r)
		overlayCritical(item, r.Critical)
		overlayChangelog(item, r.NotesMarkdown)
		overlayPubDate(item, r.PubDate)
		dropChannel(item)

		channel.AddChild(item.Copy())
	}

	doc.Indent(4)
	return doc.WriteToBytes()
}

func releaseSortKey(r Release) string {
	if r.Full != nil && r.Full.Meta.SparkleVersion != "" {
		return r.Full.Meta.SparkleVersion
	}
	return r.Version
}

// rewriteEnclosureURLs points every enclosure (full + nested deltas) at its stored
// faynoSync link by basename, leaving sparkle:edSignature and length untouched.
func rewriteEnclosureURLs(item *etree.Element, r Release) {
	links := make(map[string]string)
	if r.Full != nil {
		links[r.Full.Meta.FileName] = r.Full.Link
	}
	for _, d := range r.Deltas {
		links[d.Meta.FileName] = d.Link
	}

	for _, enc := range item.FindElements(".//enclosure") {
		urlAttr := enc.SelectAttr("url")
		if urlAttr == nil {
			continue
		}
		if link, ok := links[enclosureBasename(urlAttr.Value)]; ok && link != "" {
			urlAttr.Value = link
		}
	}
}

// overlayCritical enforces the faynoSync critical flag: keep an existing
// <sparkle:criticalUpdate> as-is (including a sparkle:version threshold) when
// critical, add a bare one only if absent; drop any when not critical.
func overlayCritical(item *etree.Element, critical bool) {
	existing := item.SelectElement("sparkle:criticalUpdate")
	if critical {
		if existing == nil {
			el := item.CreateElement("criticalUpdate")
			el.Space = "sparkle"
		}
		return
	}
	if existing != nil {
		item.RemoveChild(existing)
	}
}

// overlayChangelog replaces/inserts <description> with the faynoSync changelog
// (CDATA HTML) only when it is non-empty; an empty changelog leaves the uploaded
// item's release notes (<description>/releaseNotesLink) untouched.
func overlayChangelog(item *etree.Element, markdown string) {
	html := velopack.RenderNotesHTML(markdown)
	if html == "" {
		return
	}
	for _, d := range item.SelectElements("description") {
		item.RemoveChild(d)
	}
	desc := item.CreateElement("description")
	desc.CreateCData(html)
}

// overlayPubDate stamps the faynoSync publication date (version Updated_at): the
// date a release is available is owned by faynoSync, not the build tool. Replaces
// the raw item's <pubDate> in place (or inserts one when absent).
func overlayPubDate(item *etree.Element, pubDate string) {
	if pubDate == "" {
		return
	}
	el := item.SelectElement("pubDate")
	if el == nil {
		el = item.CreateElement("pubDate")
	}
	el.SetText(pubDate)
}

// dropChannel removes <sparkle:channel>: the materialized feed is already
// per-channel, so the tag is faynoSync-owned and redundant.
func dropChannel(item *etree.Element) {
	if ch := item.SelectElement("sparkle:channel"); ch != nil {
		item.RemoveChild(ch)
	}
}
