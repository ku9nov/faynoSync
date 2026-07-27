package sparkle

import (
	"strings"
	"testing"

	"github.com/beevik/etree"
)

const realAppcast = `<?xml version="1.0" standalone="yes"?>
<rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle" version="2.0">
    <channel>
        <title>faynosyncSparkleExample</title>
        <item>
            <title>0.0.2</title>
            <pubDate>Thu, 23 Jul 2026 12:36:45 +0300</pubDate>
            <sparkle:version>2</sparkle:version>
            <sparkle:shortVersionString>0.0.2</sparkle:shortVersionString>
            <sparkle:minimumSystemVersion>11.0</sparkle:minimumSystemVersion>
            <sparkle:releaseNotesLink>https://example.com/notes/0.0.2.html</sparkle:releaseNotesLink>
            <hardwareRequirements><requirement>arm64</requirement></hardwareRequirements>
            <enclosure url="http://cdn/faynosyncSparkleExample-0.0.2.zip" length="1063996" type="application/octet-stream" sparkle:edSignature="FULLSIG=="/>
            <sparkle:deltas>
                <enclosure url="http://cdn/faynosyncSparkleExample2-1.delta" sparkle:deltaFrom="1" length="1446" type="application/octet-stream" sparkle:deltaFromSparkleExecutableSize="977840" sparkle:deltaFromSparkleLocales="de,he,ar" sparkle:edSignature="DELTASIG=="/>
            </sparkle:deltas>
        </item>
        <item>
            <title>0.0.1</title>
            <sparkle:version>1</sparkle:version>
            <sparkle:shortVersionString>0.0.1</sparkle:shortVersionString>
            <enclosure url="http://cdn/faynosyncSparkleExample-0.0.1.zip" length="1063998" type="application/octet-stream" sparkle:edSignature="FULLSIG1=="/>
        </item>
    </channel>
</rss>`

func TestParseAppcast(t *testing.T) {
	metas, err := ParseAppcast([]byte(realAppcast))
	if err != nil {
		t.Fatalf("ParseAppcast error: %v", err)
	}
	if len(metas) != 3 {
		t.Fatalf("got %d metas, want 3: %v", len(metas), keys(metas))
	}

	full, ok := metas["faynosyncSparkleExample-0.0.2.zip"]
	if !ok {
		t.Fatal("missing full meta for 0.0.2")
	}
	if full.Kind != KindFull || full.SparkleVersion != "2" {
		t.Errorf("full meta wrong: %+v", full)
	}
	// RawItem must preserve the whole item, including non-modeled elements.
	for _, want := range []string{"sparkle:releaseNotesLink", "hardwareRequirements", "sparkle:deltas", "FULLSIG==", "sparkle:minimumSystemVersion"} {
		if !strings.Contains(full.RawItem, want) {
			t.Errorf("RawItem missing %q:\n%s", want, full.RawItem)
		}
	}

	delta, ok := metas["faynosyncSparkleExample2-1.delta"]
	if !ok {
		t.Fatal("missing delta meta")
	}
	if delta.Kind != KindDelta {
		t.Errorf("delta Kind = %q, want delta", delta.Kind)
	}
	if delta.RawItem != "" {
		t.Errorf("delta meta must not carry RawItem")
	}
}

func TestParseAppcastDecodesURLBasename(t *testing.T) {
	feed := `<rss xmlns:sparkle="s" version="2.0"><channel><item>
	<sparkle:version>3</sparkle:version>
	<enclosure url="http://cdn/path/My%20App%201.1.zip" length="5" sparkle:edSignature="S=="/>
	</item></channel></rss>`
	metas, err := ParseAppcast([]byte(feed))
	if err != nil {
		t.Fatalf("ParseAppcast error: %v", err)
	}
	if _, ok := metas["My App 1.1.zip"]; !ok {
		t.Errorf("basename not url-decoded, got keys: %v", keys(metas))
	}
}

func TestParseAppcastEmpty(t *testing.T) {
	if _, err := ParseAppcast([]byte("  ")); err == nil {
		t.Error("expected error for empty appcast")
	}
}

func parseOut(t *testing.T, data []byte) *etree.Document {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		t.Fatalf("invalid appcast xml: %v\n%s", err, data)
	}
	return doc
}

// fullAsset builds a full Asset whose RawItem carries an <item> with an optional
// block of extra (non-modeled) elements, an enclosure named zip, and a stored link.
func fullAsset(short, cf, zip, extra string) *Asset {
	raw := `<item>
  <title>` + short + `</title>
  <sparkle:version>` + cf + `</sparkle:version>
  <sparkle:shortVersionString>` + short + `</sparkle:shortVersionString>
  ` + extra + `
  <enclosure url="http://orig/` + zip + `" length="100" type="application/octet-stream" sparkle:edSignature="SIG-` + cf + `"/>
</item>`
	return &Asset{
		Link: "http://cdn/" + zip,
		Meta: SparkleMeta{FileName: zip, Kind: KindFull, SparkleVersion: cf, RawItem: raw},
	}
}

func itemsByTitle(doc *etree.Document) map[string]*etree.Element {
	out := map[string]*etree.Element{}
	for _, it := range doc.FindElements("//item") {
		if t := it.SelectElement("title"); t != nil {
			out[t.Text()] = it
		}
	}
	return out
}

func TestBuildAppcastPreservesUnknownAndRewritesURL(t *testing.T) {
	releases := []Release{
		{Version: "0.0.1", Published: true, Full: fullAsset("0.0.1", "1", "app-0.0.1.zip", "")},
		{Version: "0.0.2", Published: true, Full: fullAsset("0.0.2", "2", "app-0.0.2.zip",
			`<sparkle:releaseNotesLink>https://x/n.html</sparkle:releaseNotesLink><hardwareRequirements><requirement>arm64</requirement></hardwareRequirements><minimumAutoupdateVersion>3</minimumAutoupdateVersion>`)},
	}
	data := mustBuild(t, releases)
	s := string(data)

	// unknown / non-modeled elements survive verbatim
	for _, want := range []string{"sparkle:releaseNotesLink", "hardwareRequirements", "minimumAutoupdateVersion"} {
		if !strings.Contains(s, want) {
			t.Errorf("build dropped %q:\n%s", want, s)
		}
	}

	doc := parseOut(t, data)
	items := doc.FindElements("//item")
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2", len(items))
	}
	// newest first by sparkle:version
	if first := items[0].SelectElement("title").Text(); first != "0.0.2" {
		t.Errorf("items not sorted desc, first = %q", first)
	}

	it := itemsByTitle(doc)["0.0.2"]
	enc := it.SelectElement("enclosure")
	if got := enc.SelectAttrValue("url", ""); got != "http://cdn/app-0.0.2.zip" {
		t.Errorf("enclosure url = %q, want rewritten faynoSync link", got)
	}
	if got := enc.SelectAttrValue("sparkle:edSignature", ""); got != "SIG-2" {
		t.Errorf("edSignature not preserved: %q", got)
	}
	if got := enc.SelectAttrValue("length", ""); got != "100" {
		t.Errorf("length not preserved: %q", got)
	}
	if got := it.SelectElement("sparkle:version").Text(); got != "2" {
		t.Errorf("sparkle:version not preserved: %q", got)
	}
}

func TestBuildAppcastUnpublishedOmitted(t *testing.T) {
	releases := []Release{
		{Version: "0.0.1", Published: true, Full: fullAsset("0.0.1", "1", "a-1.zip", "")},
		{Version: "0.0.2", Published: false, Full: fullAsset("0.0.2", "2", "a-2.zip", "")},
	}
	doc := parseOut(t, mustBuild(t, releases))
	if _, ok := itemsByTitle(doc)["0.0.2"]; ok {
		t.Error("unpublished 0.0.2 must be omitted")
	}
	if len(doc.FindElements("//item")) != 1 {
		t.Fatalf("want 1 item")
	}
}

func TestBuildAppcastCriticalToggle(t *testing.T) {
	// bare add
	r := []Release{{Version: "0.0.2", Published: true, Critical: true, Full: fullAsset("0.0.2", "2", "a.zip", "")}}
	if !strings.Contains(string(mustBuild(t, r)), "sparkle:criticalUpdate") {
		t.Error("critical=true must emit sparkle:criticalUpdate")
	}
	// removal
	r[0].Critical = false
	if strings.Contains(string(mustBuild(t, r)), "criticalUpdate") {
		t.Error("critical=false must remove criticalUpdate")
	}
}

func TestBuildAppcastCriticalThresholdPreserved(t *testing.T) {
	r := []Release{{Version: "0.0.2", Published: true, Critical: true,
		Full: fullAsset("0.0.2", "2", "a.zip", `<sparkle:criticalUpdate sparkle:version="1.5"></sparkle:criticalUpdate>`)}}
	doc := parseOut(t, mustBuild(t, r))
	cu := doc.FindElement("//item/sparkle:criticalUpdate")
	if cu == nil {
		t.Fatal("criticalUpdate missing")
	}
	if got := cu.SelectAttrValue("sparkle:version", ""); got != "1.5" {
		t.Errorf("threshold not preserved, sparkle:version = %q", got)
	}
	// must not have duplicated the element
	if n := len(doc.FindElements("//item/sparkle:criticalUpdate")); n != 1 {
		t.Errorf("got %d criticalUpdate elements, want 1", n)
	}
}

func TestBuildAppcastChangelogOverlay(t *testing.T) {
	// non-empty changelog -> CDATA description overlaid
	r := []Release{{Version: "0.0.2", Published: true, NotesMarkdown: "## Fixed\n- bug",
		Full: fullAsset("0.0.2", "2", "a.zip", "")}}
	s := string(mustBuild(t, r))
	if !strings.Contains(s, "<description><![CDATA[") || !strings.Contains(s, "<h2>Fixed</h2>") {
		t.Errorf("changelog not rendered as CDATA description:\n%s", s)
	}

	// empty changelog -> raw release notes kept untouched, no description synthesized
	r2 := []Release{{Version: "0.0.2", Published: true, NotesMarkdown: "",
		Full: fullAsset("0.0.2", "2", "a.zip", `<sparkle:releaseNotesLink>https://x/n.html</sparkle:releaseNotesLink>`)}}
	s2 := string(mustBuild(t, r2))
	if !strings.Contains(s2, "sparkle:releaseNotesLink") {
		t.Errorf("empty changelog must keep raw releaseNotesLink:\n%s", s2)
	}
	if strings.Contains(s2, "<description>") {
		t.Errorf("empty changelog must not synthesize <description>:\n%s", s2)
	}
}

func TestBuildAppcastOverlaysPubDate(t *testing.T) {
	faynoDate := "Fri, 24 Jul 2026 15:17:29 +0300"
	r := []Release{{Version: "0.0.2", Published: true, PubDate: faynoDate,
		Full: fullAsset("0.0.2", "2", "a.zip", `<pubDate>Mon, 01 Jan 2020 00:00:00 +0000</pubDate>`)}}
	doc := parseOut(t, mustBuild(t, r))
	pd := doc.FindElement("//item/pubDate")
	if pd == nil || pd.Text() != faynoDate {
		t.Errorf("pubDate not overlaid with faynoSync date, got %q", textOf(pd))
	}
	if n := len(doc.FindElements("//item/pubDate")); n != 1 {
		t.Errorf("got %d pubDate elements, want 1", n)
	}
}

func textOf(el *etree.Element) string {
	if el == nil {
		return ""
	}
	return el.Text()
}

func TestBuildAppcastDropsChannel(t *testing.T) {
	r := []Release{{Version: "0.0.2", Published: true,
		Full: fullAsset("0.0.2", "2", "a.zip", `<sparkle:channel>nightly</sparkle:channel>`)}}
	if strings.Contains(string(mustBuild(t, r)), "sparkle:channel") {
		t.Error("sparkle:channel must be dropped (feed is per-channel)")
	}
}

func TestBuildAppcastDeltasRewrittenAndPreserved(t *testing.T) {
	full := fullAsset("0.0.2", "2", "app-0.0.2.zip", "")
	// inject a <sparkle:deltas> block into the raw item
	full.Meta.RawItem = strings.Replace(full.Meta.RawItem, "</item>",
		`  <sparkle:deltas>
    <enclosure url="http://orig/app2-1.delta" length="1446" type="application/octet-stream" sparkle:deltaFrom="1" sparkle:deltaFromSparkleExecutableSize="9" sparkle:edSignature="DSIG=="/>
  </sparkle:deltas>
</item>`, 1)

	r := []Release{{Version: "0.0.2", Published: true, Full: full,
		Deltas: []Asset{{Link: "http://cdn/app2-1.delta", Meta: SparkleMeta{FileName: "app2-1.delta", Kind: KindDelta}}}}}

	doc := parseOut(t, mustBuild(t, r))
	d := doc.FindElement("//sparkle:deltas/enclosure")
	if d == nil {
		t.Fatal("delta enclosure missing")
	}
	if got := d.SelectAttrValue("url", ""); got != "http://cdn/app2-1.delta" {
		t.Errorf("delta url not rewritten: %q", got)
	}
	if got := d.SelectAttrValue("sparkle:edSignature", ""); got != "DSIG==" {
		t.Errorf("delta edSignature not preserved: %q", got)
	}
	if got := d.SelectAttrValue("sparkle:deltaFromSparkleExecutableSize", ""); got != "9" {
		t.Errorf("delta extra attr not preserved: %q", got)
	}
}

func mustBuild(t *testing.T, releases []Release) []byte {
	t.Helper()
	data, err := BuildAppcast("MyApp", releases)
	if err != nil {
		t.Fatalf("BuildAppcast error: %v", err)
	}
	return data
}

func keys(m map[string]SparkleMeta) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
