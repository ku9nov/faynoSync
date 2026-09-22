package create

import (
	"bytes"
	"mime/multipart"
	"testing"
)

const velopackFeedJSON = `{"Assets":[{"Type":"Full","FileName":"MyApp-1.0.0-full.nupkg","SHA1":"a","SHA256":"b","Size":2}]}`

const sparkleAppcastXML = `<?xml version="1.0" standalone="yes"?>
<rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle" version="2.0">
    <channel>
        <item>
            <title>1.0.0</title>
            <sparkle:version>1</sparkle:version>
            <enclosure url="http://cdn/MyApp-1.0.0.zip" length="10" type="application/octet-stream" sparkle:edSignature="SIG=="/>
        </item>
    </channel>
</rss>`

type uploadedFile struct {
	name    string
	content string
}

func uploadedFiles(t *testing.T, files ...uploadedFile) []*multipart.FileHeader {
	t.Helper()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	maxContent := 0
	for _, f := range files {
		part, err := writer.CreateFormFile("file", f.name)
		if err != nil {
			t.Fatalf("CreateFormFile(%q): %v", f.name, err)
		}
		if _, err := part.Write([]byte(f.content)); err != nil {
			t.Fatalf("write %q: %v", f.name, err)
		}
		maxContent += len(f.content)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	form, err := multipart.NewReader(&body, writer.Boundary()).ReadForm(int64(maxContent) + 4096)
	if err != nil {
		t.Fatalf("ReadForm: %v", err)
	}
	return form.File["file"]
}

// The feed file is picked out of the upload by name alone; every other uploaded
// artifact must be ignored, including ones whose name merely looks similar.
func TestParseVelopackFeedSelection(t *testing.T) {
	cases := []struct {
		name    string
		files   []uploadedFile
		wantErr bool
	}{
		{
			name: "feed among artifacts",
			files: []uploadedFile{
				{"MyApp-1.0.0-full.nupkg", "binary"},
				{"releases.nightly.json", velopackFeedJSON},
			},
		},
		{
			name:  "uppercase feed name",
			files: []uploadedFile{{"RELEASES.NIGHTLY.JSON", velopackFeedJSON}},
		},
		{
			name:    "no feed file",
			files:   []uploadedFile{{"MyApp-1.0.0-full.nupkg", "binary"}},
			wantErr: true,
		},
		{
			name:    "json that is not a releases feed",
			files:   []uploadedFile{{"metadata.json", velopackFeedJSON}},
			wantErr: true,
		},
		{
			name:    "invalid feed content",
			files:   []uploadedFile{{"releases.nightly.json", "not json"}},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			meta, err := ParseVelopackFeed(uploadedFiles(t, tc.files...))
			if tc.wantErr != (err != nil) {
				t.Fatalf("ParseVelopackFeed() err = %v, wantErr = %v", err, tc.wantErr)
			}
			if err == nil {
				if _, ok := meta["MyApp-1.0.0-full.nupkg"]; !ok {
					t.Errorf("parsed meta = %v, want an entry for MyApp-1.0.0-full.nupkg", meta)
				}
			}
		})
	}
}

func TestParseSparkleAppcastSelection(t *testing.T) {
	cases := []struct {
		name    string
		files   []uploadedFile
		wantErr bool
	}{
		{
			name: "appcast among artifacts",
			files: []uploadedFile{
				{"MyApp-1.0.0.zip", "binary"},
				{"appcast.nightly.xml", sparkleAppcastXML},
			},
		},
		{
			name:  "appcast without channel suffix",
			files: []uploadedFile{{"appcast.xml", sparkleAppcastXML}},
		},
		{
			name:  "uppercase appcast name",
			files: []uploadedFile{{"APPCAST.XML", sparkleAppcastXML}},
		},
		{
			name:    "no appcast file",
			files:   []uploadedFile{{"MyApp-1.0.0.zip", "binary"}},
			wantErr: true,
		},
		{
			name:    "xml that is not an appcast",
			files:   []uploadedFile{{"manifest.xml", sparkleAppcastXML}},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			metas, err := ParseSparkleAppcast(uploadedFiles(t, tc.files...))
			if tc.wantErr != (err != nil) {
				t.Fatalf("ParseSparkleAppcast() err = %v, wantErr = %v", err, tc.wantErr)
			}
			if err == nil {
				if _, ok := metas["MyApp-1.0.0.zip"]; !ok {
					t.Errorf("parsed metas = %v, want an entry for MyApp-1.0.0.zip", metas)
				}
			}
		})
	}
}
