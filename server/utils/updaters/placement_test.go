package updaters

import (
	"path"
	"testing"

	"faynoSync/server/utils/updaters/sparkle"
	"faynoSync/server/utils/updaters/velopack"
)

func platformCtx(platform, arch string) map[string]interface{} {
	return map[string]interface{}{
		"app_name": "MyApp",
		"platform": platform,
		"arch":     arch,
		"channel":  "nightly",
		"version":  "0.0.1",
		"api_url":  "https://cdn",
	}
}

var platformTuples = []struct{ platform, arch string }{
	{"darwin", "arm64"},
	{"darwin", "amd64"},
	{"windows", "x64"},
}

// Regression for the multi-platform feed bug: uploading a version's artifacts for
// a second platform must place both the archive AND the materialized appcast under
// that platform's own directory, never colliding with or overwriting another
// platform/arch. Archive and appcast for one tuple must share a directory so the
// feed and its assets stay co-located.
func TestSparklePlacementIsolatedPerPlatform(t *testing.T) {
	archiveDirs := map[string]struct{ platform, arch string }{}
	for _, tp := range platformTuples {
		ctx := platformCtx(tp.platform, tp.arch)

		_, archiveKey := BuildS3Key(ctx, "acme", "new.zip", "MyApp-0.0.1.zip", sparkle.UpdaterType)
		_, appcastKey := BuildS3Key(ctx, "acme", "new.xml", "appcast.nightly.xml", sparkle.UpdaterType)

		if prev, ok := archiveDirs[path.Dir(archiveKey)]; ok {
			t.Fatalf("archive dir collision %q between %+v and %+v", path.Dir(archiveKey), prev, tp)
		}
		archiveDirs[path.Dir(archiveKey)] = tp

		if path.Dir(archiveKey) != path.Dir(appcastKey) {
			t.Errorf("archive %q and appcast %q not co-located for %+v", archiveKey, appcastKey, tp)
		}

		// uploaded appcast must route onto the exact key the materializer writes
		wantAppcast := sparkle.AppcastObjectKey("acme", "MyApp", tp.platform, tp.arch, "nightly")
		if appcastKey != wantAppcast {
			t.Errorf("appcast routed to %q, want materialized key %q", appcastKey, wantAppcast)
		}
	}
}

func TestVelopackPlacementIsolatedPerPlatform(t *testing.T) {
	pkgDirs := map[string]struct{ platform, arch string }{}
	for _, tp := range platformTuples {
		ctx := platformCtx(tp.platform, tp.arch)

		_, pkgKey := BuildS3Key(ctx, "acme", "", "MyApp-0.0.1-full.nupkg", velopack.UpdaterType)
		feedKey := velopack.FeedObjectKey("acme", "MyApp", tp.platform, tp.arch, "nightly")

		if prev, ok := pkgDirs[path.Dir(pkgKey)]; ok {
			t.Fatalf("package dir collision %q between %+v and %+v", path.Dir(pkgKey), prev, tp)
		}
		pkgDirs[path.Dir(pkgKey)] = tp

		if path.Dir(pkgKey) != path.Dir(feedKey) {
			t.Errorf("package %q and feed %q not co-located for %+v", pkgKey, feedKey, tp)
		}
	}
}
