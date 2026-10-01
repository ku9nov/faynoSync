package updaters

import "testing"

func TestTauriUpdateURL(t *testing.T) {
	cases := []struct {
		name     string
		response map[string]interface{}
		want     string
		wantOK   bool
	}{
		{
			name:     "macOS bundle wins over dmg and sig",
			response: map[string]interface{}{"update_url_dmg": "dmg", "update_url_app.tar.gz": "bundle", "update_url_sig": "sig"},
			want:     "bundle",
			wantOK:   true,
		},
		{
			name:     "legacy gz bundle wins over dmg",
			response: map[string]interface{}{"update_url_dmg": "dmg", "update_url_gz": "bundle", "update_url_sig": "sig"},
			want:     "bundle",
			wantOK:   true,
		},
		{
			name:     "v1 AppImage bundle case-insensitive",
			response: map[string]interface{}{"update_url_AppImage.tar.gz": "bundle", "update_url_deb": "deb"},
			want:     "bundle",
			wantOK:   true,
		},
		{
			name:     "v1 nsis bundle wins over exe",
			response: map[string]interface{}{"update_url_exe": "exe", "update_url_nsis.zip": "bundle"},
			want:     "bundle",
			wantOK:   true,
		},
		{
			name:     "v2 windows installer",
			response: map[string]interface{}{"update_url_exe": "exe", "update_url_sig": "sig"},
			want:     "exe",
			wantOK:   true,
		},
		{
			name:     "unknown packages fall back deterministically",
			response: map[string]interface{}{"update_url_rpm": "rpm", "update_url_deb": "deb"},
			want:     "deb",
			wantOK:   true,
		},
		{
			name:     "only signature",
			response: map[string]interface{}{"update_url_sig": "sig", "changelog": "notes"},
			wantOK:   false,
		},
		{
			name:     "only dmg",
			response: map[string]interface{}{"update_url_dmg": "dmg", "update_url_sig": "sig"},
			wantOK:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 20; i++ {
				got, ok := tauriUpdateURL(tc.response)
				if ok != tc.wantOK || got != tc.want {
					t.Fatalf("tauriUpdateURL() = %q, %v, want %q, %v", got, ok, tc.want, tc.wantOK)
				}
			}
		})
	}
}

func TestBuildResponseTauriDeterministic(t *testing.T) {
	for i := 0; i < 50; i++ {
		response := map[string]interface{}{
			"update_available":      true,
			"update_url_dmg":        "dmg",
			"update_url_app.tar.gz": "bundle",
			"update_url_sig":        "sigfile",
			"signature":             "c2ln",
			"changelog":             "notes",
		}
		got, status := BuildResponse(response, true, false, "1.0.1", "tauri")
		if status != 200 || got["url"] != "bundle" || got["signature"] != "c2ln" || got["notes"] != "notes" || got["version"] != "1.0.1" {
			t.Fatalf("BuildResponse tauri = %v (%d)", got, status)
		}
	}
}

func TestBuildResponseTauriNoPayload(t *testing.T) {
	for _, response := range []map[string]interface{}{
		{"update_available": true, "update_url_sig": "sigfile", "signature": "c2ln", "changelog": "notes"},
		{"update_available": true, "update_url_dmg": "dmg", "signature": "c2ln", "changelog": "notes"},
	} {
		got, status := BuildResponse(response, true, false, "1.0.1", "tauri")
		if status != 204 || got["url"] != nil {
			t.Fatalf("BuildResponse tauri without payload = %v (%d), want 204", got, status)
		}
	}
}
