package updaters

import (
	"mime/multipart"
	"testing"
)

func headers(names ...string) []*multipart.FileHeader {
	out := make([]*multipart.FileHeader, 0, len(names))
	for _, n := range names {
		out = append(out, &multipart.FileHeader{Filename: n})
	}
	return out
}

// Every file validator decides on the file name alone. Pinned here because the
// presigned flow has to run the same checks with names only, before any bytes exist.
func TestValidateFilesDispatch(t *testing.T) {
	cases := []struct {
		name        string
		updaterType string
		files       []*multipart.FileHeader
		wantErr     bool
	}{
		{"empty updater skips validation", "", nil, false},
		{"unknown updater accepts anything", "manual", headers("MyApp.dmg"), false},
		{"tauri has no file validator", "tauri", headers("MyApp.tar.gz"), false},

		{"electron-builder with yml", "electron-builder", headers("MyApp.exe", "latest.yml"), false},
		{"electron-builder with yaml", "electron-builder", headers("MyApp.exe", "latest.yaml"), false},
		{"electron-builder uppercase yml", "electron-builder", headers("MyApp.exe", "LATEST.YML"), false},
		{"electron-builder without feed", "electron-builder", headers("MyApp.exe"), true},

		{"squirrel_windows with RELEASES", "squirrel_windows", headers("MyApp.nupkg", "RELEASES"), false},
		{"squirrel_windows lowercase releases", "squirrel_windows", headers("MyApp.nupkg", "releases"), false},
		{"squirrel_windows rejects suffixed name", "squirrel_windows", headers("MyApp.nupkg", "RELEASES.txt"), true},
		{"squirrel_windows without RELEASES", "squirrel_windows", headers("MyApp.nupkg"), true},

		{"squirrel_darwin with zip", "squirrel_darwin", headers("MyApp.zip"), false},
		{"squirrel_darwin without zip", "squirrel_darwin", headers("MyApp.dmg"), true},

		{"velopack with feed and package", "velopack", headers("releases.nightly.json", "MyApp-1.0.0-full.nupkg"), false},
		{"velopack without feed", "velopack", headers("MyApp-1.0.0-full.nupkg"), true},

		{"sparkle with appcast and archive", "sparkle", headers("appcast.nightly.xml", "MyApp-1.0.0.zip"), false},
		{"sparkle without appcast", "sparkle", headers("MyApp-1.0.0.zip"), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateFiles(tc.files, tc.updaterType)
			if tc.wantErr != (err != nil) {
				t.Errorf("ValidateFiles(%q) err = %v, wantErr = %v", tc.updaterType, err, tc.wantErr)
			}
		})
	}
}

func TestValidateParamsDispatch(t *testing.T) {
	cases := []struct {
		name        string
		updaterType string
		params      map[string]interface{}
		wantErr     bool
	}{
		{"empty updater skips validation", "", map[string]interface{}{}, false},
		{"non-tauri needs no signature", "electron-builder", map[string]interface{}{}, false},
		{"tauri with signature", "tauri", map[string]interface{}{"signature": "dW50cnVzdGVk"}, false},
		{"tauri without signature", "tauri", map[string]interface{}{}, true},
		{"tauri with empty signature", "tauri", map[string]interface{}{"signature": ""}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateParams(tc.params, tc.updaterType)
			if tc.wantErr != (err != nil) {
				t.Errorf("ValidateParams(%q) err = %v, wantErr = %v", tc.updaterType, err, tc.wantErr)
			}
		})
	}
}
