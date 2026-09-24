package create

import (
	"context"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"faynoSync/server/utils/storage"

	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson"
)

const (
	testMD5    = "fed304a43b43b889ac1b948e073928d0"
	testSHA256 = "d73428d4e21289de53fa964274ed1dc0e39a4f58e3825fc69617c9d3dee366d7"
)

var testSHA512 = strings.Repeat("ab", 64)

func manifestJSON(entries ...string) string {
	return "[" + strings.Join(entries, ",") + "]"
}

func manifestEntry(name string, length int64) string {
	return `{"name":"` + name + `","md5":"` + testMD5 + `","sha256":"` + testSHA256 + `","sha512":"` + testSHA512 + `","length":` + strconv.FormatInt(length, 10) + `}`
}

func TestParsePresignedManifest(t *testing.T) {
	upper := `{"name":"App.exe","md5":"` + strings.ToUpper(testMD5) + `","sha256":"` + strings.ToUpper(testSHA256) + `","sha512":"` + testSHA512 + `","length":40}`
	manifest, err := parsePresignedManifest(manifestJSON(upper, manifestEntry("App.dmg", 40)))
	if err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	if manifest[0].MD5 != testMD5 || manifest[0].SHA256 != testSHA256 {
		t.Errorf("digests are not normalized to lower case: %+v", manifest[0])
	}

	// Only md5 is required: sha256/sha512 matter only to TUF, and length comes from storage.
	minimal, err := parsePresignedManifest(manifestJSON(`{"name":"App.exe","md5":"` + testMD5 + `"}`))
	if err != nil {
		t.Fatalf("md5-only manifest rejected: %v", err)
	}
	if hashes := declaredHashes(minimal[0]); len(hashes) != 0 {
		t.Errorf("undeclared hashes must stay absent, got %v", hashes)
	}
	if hashes := declaredHashes(manifest[1]); hashes["sha256"] != testSHA256 || hashes["sha512"] != testSHA512 {
		t.Errorf("declared hashes lost: %v", hashes)
	}

	cases := map[string]string{
		"missing":             "",
		"not json":            "{",
		"empty":               "[]",
		"path traversal":      manifestJSON(manifestEntry("../App.exe", 40)),
		"nested path":         manifestJSON(manifestEntry("dir/App.exe", 40)),
		"backslash":           manifestJSON(manifestEntry(`dir\\App.exe`, 40)),
		"dot":                 manifestJSON(manifestEntry("..", 40)),
		"duplicate":           manifestJSON(manifestEntry("App.exe", 40), manifestEntry("App.exe", 40)),
		"negative length":     manifestJSON(manifestEntry("App.exe", -1)),
		"over single PUT cap": manifestJSON(manifestEntry("App.exe", maxPresignedFileSize+1)),
		"short md5":           manifestJSON(`{"name":"App.exe","md5":"abc","sha256":"` + testSHA256 + `","sha512":"` + testSHA512 + `","length":1}`),
		"missing md5":         manifestJSON(`{"name":"App.exe","sha256":"` + testSHA256 + `","length":1}`),
		"non-hex sha512":      manifestJSON(`{"name":"App.exe","md5":"` + testMD5 + `","sha512":"` + strings.Repeat("zz", 64) + `","length":1}`),
		"non-hex sha256":      manifestJSON(`{"name":"App.exe","md5":"` + testMD5 + `","sha256":"` + strings.Repeat("zz", 32) + `","sha512":"` + testSHA512 + `","length":1}`),
	}
	for name, raw := range cases {
		if _, err := parsePresignedManifest(raw); err == nil {
			t.Errorf("%s: manifest accepted", name)
		}
	}
}

type fakeUploader struct {
	stats map[string]storage.ObjectStat
}

func (f *fakeUploader) PresignPutObject(context.Context, string, string, []byte, int64, string, time.Duration) (storage.PresignedRequest, error) {
	return storage.PresignedRequest{}, nil
}

func (f *fakeUploader) StatObject(_ context.Context, _ string, key string) (storage.ObjectStat, error) {
	stat, ok := f.stats[key]
	if !ok {
		return storage.ObjectStat{}, storage.ErrObjectNotFound
	}
	return stat, nil
}

func (f *fakeUploader) OpenObject(context.Context, string, string) (io.ReadCloser, error) {
	return nil, storage.ErrObjectNotFound
}

func (f *fakeUploader) PublicObjectURL(string, string) string { return "" }

func TestVerifyPresignedFile(t *testing.T) {
	file := pendingFile{Name: "App.exe", PendingKey: "pending/x/0", MD5: testMD5, Length: 40}

	cases := []struct {
		name     string
		length   int64
		stat     *storage.ObjectStat
		wantErr  string
		wantSize int64
	}{
		{name: "matches", stat: &storage.ObjectStat{Size: 40, MD5: testMD5}, wantSize: 40},
		{name: "undeclared length is taken from storage", length: -1, stat: &storage.ObjectStat{Size: 57, MD5: testMD5}, wantSize: 57},
		{name: "not uploaded", wantErr: "not uploaded"},
		{name: "size differs", stat: &storage.ObjectStat{Size: 41, MD5: testMD5}, wantErr: "declared 40"},
		{name: "md5 differs", stat: &storage.ObjectStat{Size: 40, MD5: strings.Repeat("0", 32)}, wantErr: "declared MD5"},
		{name: "no md5 from storage", stat: &storage.ObjectStat{Size: 40}, wantErr: "no MD5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uploader := &fakeUploader{stats: map[string]storage.ObjectStat{}}
			if tc.stat != nil {
				uploader.stats[file.PendingKey] = *tc.stat
			}
			declared := file
			if tc.length == -1 {
				declared.Length = 0
			}
			size, err := verifyPresignedFile(context.Background(), uploader, "bucket", declared)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr == "" && size != tc.wantSize {
				t.Errorf("size = %d, want %d", size, tc.wantSize)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestPendingUploadBSONRoundTrip(t *testing.T) {
	in := pendingUpload{
		ID:    "0123456789abcdef0123456789abcdef",
		State: pendingStatePending,
		Files: []pendingFile{
			{Name: "releases.nightly.json", PendingKey: "pending/x/0", Inline: true, Hashes: map[string]string{"sha256": testSHA256}, Length: 10},
			{Name: "App-full.nupkg", PendingKey: "pending/x/1", MD5: testMD5, Hashes: map[string]string{"sha256": testSHA256, "sha512": testSHA512}, Length: 40},
		},
		ExpiresAt: time.Now().Truncate(time.Millisecond).UTC(),
	}
	raw, err := bson.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out pendingUpload
	if err := bson.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.Files[0].Inline || out.Files[1].Inline || out.Files[1].MD5 != testMD5 || out.Files[1].Hashes["sha512"] != testSHA512 {
		t.Errorf("round trip lost data: %+v", out.Files)
	}
}

func TestPresignedPutTTL(t *testing.T) {
	cases := []struct {
		raw  string
		want time.Duration
	}{
		{"", defaultPresignedPutTTL},
		{"2h", 2 * time.Hour},
		{"168h", maxPresignedPutTTL},
		{"169h", defaultPresignedPutTTL},
		{"0s", defaultPresignedPutTTL},
		{"-5m", defaultPresignedPutTTL},
		{"not-a-duration", defaultPresignedPutTTL},
	}
	for _, tc := range cases {
		env := viper.New()
		env.Set("PRESIGNED_UPLOAD_URL_TTL", tc.raw)
		if got := presignedPutTTL(env); got != tc.want {
			t.Errorf("PRESIGNED_UPLOAD_URL_TTL=%q: got %s, want %s", tc.raw, got, tc.want)
		}
	}
}
