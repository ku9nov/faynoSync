package sparkle

import (
	"mime/multipart"
	"testing"
)

func files(names ...string) []*multipart.FileHeader {
	out := make([]*multipart.FileHeader, 0, len(names))
	for _, n := range names {
		out = append(out, &multipart.FileHeader{Filename: n})
	}
	return out
}

func TestValidateArchivesInAppcast(t *testing.T) {
	metas := map[string]SparkleMeta{
		"MyApp-0.0.1.zip": {FileName: "MyApp-0.0.1.zip", Kind: KindFull},
		"MyApp2-1.delta":  {FileName: "MyApp2-1.delta", Kind: KindDelta},
	}
	cases := []struct {
		name    string
		files   []*multipart.FileHeader
		wantErr bool
	}{
		{"archive present", files("appcast.nightly.xml", "MyApp-0.0.1.zip"), false},
		{"archive + delta present", files("appcast.xml", "MyApp-0.0.1.zip", "MyApp2-1.delta"), false},
		{"stale appcast misses archive", files("appcast.xml", "MyApp-0.0.2.zip"), true},
		{"delta missing from appcast", files("appcast.xml", "MyApp-0.0.1.zip", "MyApp2-2.delta"), true},
		{"appcast alone is not checked", files("appcast.xml"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateArchivesInAppcast(tc.files, metas)
			if tc.wantErr != (err != nil) {
				t.Errorf("ValidateArchivesInAppcast() err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	v := NewFileValidator(UpdaterType)
	cases := []struct {
		name    string
		files   []*multipart.FileHeader
		wantErr bool
	}{
		{"full+appcast", files("appcast.nightly.xml", "MyApp-0.0.2.zip"), false},
		{"full+delta+appcast", files("appcast.xml", "MyApp-0.0.2.zip", "MyApp2-1.delta"), false},
		{"dmg", files("appcast.xml", "MyApp.dmg"), false},
		{"tar.gz", files("appcast.xml", "MyApp.tar.gz"), false},
		{"no appcast", files("MyApp-0.0.2.zip"), true},
		{"two appcasts", files("appcast.stable.xml", "appcast.nightly.xml", "MyApp.zip"), true},
		{"no full archive", files("appcast.xml", "MyApp2-1.delta"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.files)
			if tc.wantErr != (err != nil) {
				t.Errorf("Validate() err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}
