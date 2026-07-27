package sparkle

import (
	"strings"
	"testing"
)

func TestAppcastObjectKey(t *testing.T) {
	got := AppcastObjectKey("acme", "MyApp", "darwin", "arm64", "nightly")
	want := "sparkle/acme/MyApp/darwin/arm64/appcast.nightly.xml"
	if got != want {
		t.Errorf("AppcastObjectKey = %q, want %q", got, want)
	}
}

// Regression for the multi-platform feed bug: uploading a version's artifacts for
// a second platform must land the appcast on a distinct key, never overwriting or
// colliding with another platform/arch feed.
func TestAppcastObjectKeyDistinctPerPlatform(t *testing.T) {
	tuples := []struct{ platform, arch string }{
		{"darwin", "arm64"},
		{"darwin", "amd64"},
		{"windows", "x64"},
	}
	seen := map[string]struct{ platform, arch string }{}
	for _, tp := range tuples {
		key := AppcastObjectKey("acme", "MyApp", tp.platform, tp.arch, "nightly")
		if prev, ok := seen[key]; ok {
			t.Fatalf("key collision %q between %+v and %+v", key, prev, tp)
		}
		seen[key] = tp
		if !strings.Contains(key, "/"+tp.platform+"/"+tp.arch+"/") {
			t.Errorf("key %q missing platform/arch segment %s/%s", key, tp.platform, tp.arch)
		}
	}
}

// Owners with no created channels (and uploads without platform/arch) must not
// produce "appcast..xml" or empty path segments.
func TestAppcastObjectKeyOmitsEmptyComponents(t *testing.T) {
	cases := []struct {
		platform, arch, channel string
		want                    string
	}{
		{"darwin", "arm64", "", "sparkle/acme/MyApp/darwin/arm64/appcast.xml"},
		{"", "", "nightly", "sparkle/acme/MyApp/appcast.nightly.xml"},
		{"", "", "", "sparkle/acme/MyApp/appcast.xml"},
		{"darwin", "", "", "sparkle/acme/MyApp/darwin/appcast.xml"},
	}
	for _, c := range cases {
		if got := AppcastObjectKey("acme", "MyApp", c.platform, c.arch, c.channel); got != c.want {
			t.Errorf("AppcastObjectKey(platform=%q, arch=%q, channel=%q) = %q, want %q", c.platform, c.arch, c.channel, got, c.want)
		}
	}
}

func TestGetUpdaterType(t *testing.T) {
	if got := NewFileValidator(UpdaterType).GetUpdaterType(); got != UpdaterType {
		t.Errorf("GetUpdaterType = %q, want %q", got, UpdaterType)
	}
}

func TestEnclosureBasename(t *testing.T) {
	cases := map[string]string{
		"":                                 "",
		"file.zip":                         "file.zip",
		"http://cdn/app-0.0.1.zip":         "app-0.0.1.zip",
		"http://cdn/path/My%20App%201.zip": "My App 1.zip",
	}
	for in, want := range cases {
		if got := enclosureBasename(in); got != want {
			t.Errorf("enclosureBasename(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestItemSparkleVersionAbsent(t *testing.T) {
	feed := `<rss xmlns:sparkle="s" version="2.0"><channel><item>
	<title>no version</title>
	<enclosure url="http://cdn/a.zip" length="1" sparkle:edSignature="S=="/>
	</item></channel></rss>`
	metas, err := ParseAppcast([]byte(feed))
	if err != nil {
		t.Fatalf("ParseAppcast error: %v", err)
	}
	m, ok := metas["a.zip"]
	if !ok {
		t.Fatal("missing meta for a.zip")
	}
	if m.SparkleVersion != "" {
		t.Errorf("SparkleVersion = %q, want empty when <sparkle:version> absent", m.SparkleVersion)
	}
}

func TestParseAppcastSkipsItemsWithoutEnclosure(t *testing.T) {
	feed := `<rss xmlns:sparkle="s" version="2.0"><channel>
	<item><title>no enclosure</title></item>
	<item><title>empty url</title><enclosure url="" length="1"/></item>
	<item><title>ok</title><sparkle:version>1</sparkle:version><enclosure url="http://cdn/b.zip" length="1" sparkle:edSignature="S=="/></item>
	</channel></rss>`
	metas, err := ParseAppcast([]byte(feed))
	if err != nil {
		t.Fatalf("ParseAppcast error: %v", err)
	}
	if len(metas) != 1 {
		t.Fatalf("got %d metas, want 1 (items without a usable enclosure skipped)", len(metas))
	}
	if _, ok := metas["b.zip"]; !ok {
		t.Errorf("expected b.zip meta, got %v", keys(metas))
	}
}

// pubDate is inserted (not just replaced) when the raw item carries none.
func TestBuildAppcastInsertsPubDateWhenAbsent(t *testing.T) {
	faynoDate := "Fri, 24 Jul 2026 15:17:29 +0300"
	r := []Release{{Version: "0.0.2", Published: true, PubDate: faynoDate,
		Full: fullAsset("0.0.2", "2", "a.zip", "")}} // raw has no <pubDate>
	doc := parseOut(t, mustBuild(t, r))
	pd := doc.FindElement("//item/pubDate")
	if pd == nil || pd.Text() != faynoDate {
		t.Errorf("pubDate not inserted, got %q", textOf(pd))
	}
	if n := len(doc.FindElements("//item/pubDate")); n != 1 {
		t.Errorf("got %d pubDate elements, want 1", n)
	}
}

// A non-empty changelog replaces an existing <description>, leaving exactly one.
func TestBuildAppcastReplacesExistingDescription(t *testing.T) {
	r := []Release{{Version: "0.0.2", Published: true, NotesMarkdown: "## New\n- thing",
		Full: fullAsset("0.0.2", "2", "a.zip", `<description>stale notes</description>`)}}
	s := string(mustBuild(t, r))
	if strings.Contains(s, "stale notes") {
		t.Errorf("existing description must be replaced:\n%s", s)
	}
	if !strings.Contains(s, "<![CDATA[") || !strings.Contains(s, "<h2>New</h2>") {
		t.Errorf("changelog not rendered as CDATA description:\n%s", s)
	}
	doc := parseOut(t, []byte(s))
	if n := len(doc.FindElements("//item/description")); n != 1 {
		t.Errorf("got %d description elements, want 1", n)
	}
}

// releaseSortKey falls back to Version when a release has no Full asset; such a
// release still participates in sorting but is omitted from the emitted feed.
func TestBuildAppcastSortsNilFullByVersion(t *testing.T) {
	releases := []Release{
		{Version: "0.0.3", Published: true}, // no Full -> sort by Version, omitted
		{Version: "0.0.1", Published: true, Full: fullAsset("0.0.1", "1", "a-1.zip", "")},
		{Version: "0.0.2", Published: true, Full: fullAsset("0.0.2", "2", "a-2.zip", "")},
	}
	doc := parseOut(t, mustBuild(t, releases))
	items := doc.FindElements("//item")
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2 (nil-Full release omitted)", len(items))
	}
	if first := items[0].SelectElement("title").Text(); first != "0.0.2" {
		t.Errorf("first item = %q, want 0.0.2", first)
	}
}
