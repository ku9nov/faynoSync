package sparkle

import (
	"encoding/xml"
	"strings"
	"testing"
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
            <enclosure url="http://cdn/faynosyncSparkleExample-0.0.2.zip" length="1063996" type="application/octet-stream" sparkle:edSignature="FULLSIG=="/>
            <sparkle:deltas>
                <enclosure url="http://cdn/faynosyncSparkleExample2-1.delta" sparkle:deltaFrom="1" length="1446" type="application/octet-stream" sparkle:deltaFromSparkleExecutableSize="977840" sparkle:deltaFromSparkleLocales="de,he,ar" sparkle:edSignature="DELTASIG=="/>
            </sparkle:deltas>
        </item>
        <item>
            <title>0.0.1</title>
            <sparkle:version>1</sparkle:version>
            <sparkle:shortVersionString>0.0.1</sparkle:shortVersionString>
            <sparkle:minimumSystemVersion>11.0</sparkle:minimumSystemVersion>
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
		t.Fatalf("got %d metas, want 3: %+v", len(metas), metas)
	}

	full, ok := metas["faynosyncSparkleExample-0.0.2.zip"]
	if !ok {
		t.Fatal("missing full meta for 0.0.2")
	}
	if full.Kind != KindFull {
		t.Errorf("Kind = %q, want full", full.Kind)
	}
	if full.SparkleVersion != "2" || full.ShortVersionString != "0.0.2" || full.MinimumSystemVersion != "11.0" {
		t.Errorf("item-level fields not parsed: %+v", full)
	}
	if full.EdSignature != "FULLSIG==" || full.Length != 1063996 {
		t.Errorf("enclosure fields not parsed: %+v", full)
	}

	delta, ok := metas["faynosyncSparkleExample2-1.delta"]
	if !ok {
		t.Fatal("missing delta meta")
	}
	if delta.Kind != KindDelta {
		t.Errorf("Kind = %q, want delta", delta.Kind)
	}
	if delta.DeltaFrom != "1" || delta.DeltaFromExecutableSize != "977840" || delta.DeltaFromLocales != "de,he,ar" {
		t.Errorf("delta fields not parsed: %+v", delta)
	}
	if delta.EdSignature != "DELTASIG==" || delta.Length != 1446 {
		t.Errorf("delta enclosure fields not parsed: %+v", delta)
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

func decodeAppcast(t *testing.T, data []byte) appcastFeed {
	t.Helper()
	var feed appcastFeed
	if err := xml.Unmarshal(data, &feed); err != nil {
		t.Fatalf("invalid appcast xml: %v\n%s", err, data)
	}
	return feed
}

func fullAsset(version string) *Asset {
	return &Asset{
		Link: "http://cdn/" + version + ".zip",
		Meta: SparkleMeta{
			FileName:             version + ".zip",
			Kind:                 KindFull,
			EdSignature:          "SIG-" + version,
			Length:               100,
			SparkleVersion:       version + "-cf",
			ShortVersionString:   version,
			MinimumSystemVersion: "11.0",
		},
	}
}

func TestBuildAppcastRoundTripPassThrough(t *testing.T) {
	releases := []Release{
		{Version: "0.0.1", Published: true, Full: fullAsset("0.0.1")},
		{Version: "0.0.2", Published: true, Full: fullAsset("0.0.2")},
	}
	data, err := BuildAppcast("MyApp", releases)
	if err != nil {
		t.Fatalf("BuildAppcast error: %v", err)
	}
	if !strings.HasPrefix(string(data), "<?xml") {
		t.Error("missing xml declaration")
	}
	feed := decodeAppcast(t, data)
	if len(feed.Items) != 2 {
		t.Fatalf("got %d items, want 2", len(feed.Items))
	}
	// newest first
	if feed.Items[0].Title != "0.0.2" {
		t.Errorf("items not sorted desc: first title = %q", feed.Items[0].Title)
	}
	// sparkle:version (CFBundleVersion) passed through, NOT the marketing version
	if feed.Items[0].SparkleVersion != "0.0.2-cf" {
		t.Errorf("sparkle:version = %q, want pass-through 0.0.2-cf", feed.Items[0].SparkleVersion)
	}
	if feed.Items[0].Enclosure.EdSignature != "SIG-0.0.2" {
		t.Errorf("edSignature not passed through: %q", feed.Items[0].Enclosure.EdSignature)
	}
	if feed.Items[0].Enclosure.URL != "http://cdn/0.0.2.zip" {
		t.Errorf("enclosure url = %q, want the faynoSync link", feed.Items[0].Enclosure.URL)
	}
}

func TestBuildAppcastUnpublishedOmitted(t *testing.T) {
	releases := []Release{
		{Version: "0.0.1", Published: true, Full: fullAsset("0.0.1")},
		{Version: "0.0.2", Published: false, Full: fullAsset("0.0.2")},
	}
	feed := decodeAppcast(t, mustBuild(t, releases))
	for _, it := range feed.Items {
		if it.Title == "0.0.2" {
			t.Error("unpublished 0.0.2 must be omitted")
		}
	}
	if len(feed.Items) != 1 {
		t.Fatalf("got %d items, want 1", len(feed.Items))
	}
}

func TestBuildAppcastCritical(t *testing.T) {
	releases := []Release{
		{Version: "0.0.2", Published: true, Critical: true, Full: fullAsset("0.0.2")},
	}
	data := mustBuild(t, releases)
	if !strings.Contains(string(data), "<sparkle:criticalUpdate>") {
		t.Errorf("critical release must emit sparkle:criticalUpdate:\n%s", data)
	}

	releases[0].Critical = false
	data = mustBuild(t, releases)
	if strings.Contains(string(data), "criticalUpdate") {
		t.Errorf("non-critical release must not emit criticalUpdate:\n%s", data)
	}
}

func TestBuildAppcastChangelogCDATA(t *testing.T) {
	releases := []Release{
		{Version: "0.0.2", Published: true, NotesMarkdown: "## Fixed\n- a bug", Full: fullAsset("0.0.2")},
	}
	data := mustBuild(t, releases)
	s := string(data)
	if !strings.Contains(s, "<description><![CDATA[") {
		t.Errorf("changelog must render as CDATA description:\n%s", s)
	}
	if !strings.Contains(s, "<h2>Fixed</h2>") {
		t.Errorf("markdown must be rendered to HTML:\n%s", s)
	}
}

func TestBuildAppcastDeltasPassThrough(t *testing.T) {
	r := Release{
		Version:   "0.0.2",
		Published: true,
		Full:      fullAsset("0.0.2"),
		Deltas: []Asset{{
			Link: "http://cdn/app-1.delta",
			Meta: SparkleMeta{
				Kind:                    KindDelta,
				EdSignature:             "DSIG==",
				Length:                  1446,
				DeltaFrom:               "1",
				DeltaFromExecutableSize: "977840",
				DeltaFromLocales:        "de,he",
			},
		}},
	}
	feed := decodeAppcast(t, mustBuild(t, []Release{r}))
	if len(feed.Items) != 1 {
		t.Fatalf("got %d items", len(feed.Items))
	}
	if len(feed.Items[0].Deltas.Enclosures) != 1 {
		t.Fatalf("delta enclosure missing")
	}
	d := feed.Items[0].Deltas.Enclosures[0]
	if d.URL != "http://cdn/app-1.delta" || d.EdSignature != "DSIG==" || d.DeltaFrom != "1" {
		t.Errorf("delta not passed through: %+v", d)
	}
	if d.DeltaFromExecutableSize != "977840" || d.DeltaFromLocales != "de,he" {
		t.Errorf("delta size/locales not passed through: %+v", d)
	}
}

func TestBuildAppcastNoFullSkipped(t *testing.T) {
	releases := []Release{
		{Version: "0.0.2", Published: true, Deltas: []Asset{{Link: "x", Meta: SparkleMeta{Kind: KindDelta}}}},
	}
	feed := decodeAppcast(t, mustBuild(t, releases))
	if len(feed.Items) != 0 {
		t.Errorf("release without a full archive must be skipped, got %d items", len(feed.Items))
	}
}

func TestAppcastObjectKey(t *testing.T) {
	got := AppcastObjectKey("acme", "MyApp", "osx", "arm64", "nightly")
	want := "sparkle/acme/MyApp/osx/arm64/appcast.nightly.xml"
	if got != want {
		t.Errorf("AppcastObjectKey = %q, want %q", got, want)
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
