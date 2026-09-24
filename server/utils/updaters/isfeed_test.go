package updaters

import "testing"

func TestIsFeedFile(t *testing.T) {
	cases := []struct {
		updater  string
		fileName string
		want     bool
	}{
		{"electron-builder", "latest.yml", true},
		{"electron-builder", "latest-mac.yml", true},
		{"electron-builder", "latest-linux.yaml", true},
		{"electron-builder", "MyApp-1.2.3.exe", false},
		{"electron-builder", "MyApp-1.2.3.exe.blockmap", false},
		{"electron-builder", "MyApp-1.2.3-mac.zip", false},

		{"squirrel_windows", "RELEASES", true},
		{"squirrel_windows", "releases", true},
		{"squirrel_windows", "MyApp-1.2.3-full.nupkg", false},
		{"squirrel_windows", "MyApp-1.2.3-delta.nupkg", false},
		{"squirrel_windows", "Setup.exe", false},

		{"squirrel_darwin", "MyApp-1.2.3.zip", false},

		{"velopack", "releases.nightly.json", true},
		{"velopack", "RELEASES.stable.JSON", true},
		{"velopack", "HelloVelopack-1.2.3-full.nupkg", false},
		{"velopack", "HelloVelopack-1.2.3-delta.nupkg", false},
		{"velopack", "HelloVelopack-nightly-Setup.exe", false},

		{"sparkle", "appcast.xml", true},
		{"sparkle", "appcast.nightly.xml", true},
		{"sparkle", "MyApp-1.2.3.dmg", false},
		{"sparkle", "MyApp-1.2.3.delta", false},

		{"tauri", "MyApp.AppImage", false},
		{"manual", "MyApp.deb", false},
		{"manual", "latest.yml", false},
		{"", "latest.yml", false},
		{"nonexistent-updater", "latest.yml", false},
	}

	for _, tc := range cases {
		if got := IsFeedFile(tc.fileName, tc.updater); got != tc.want {
			t.Errorf("IsFeedFile(%q, %q) = %v, want %v", tc.fileName, tc.updater, got, tc.want)
		}
	}
}
