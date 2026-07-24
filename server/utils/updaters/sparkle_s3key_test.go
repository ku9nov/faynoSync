package updaters

import (
	"testing"

	"faynoSync/server/utils/updaters/sparkle"
)

func sparkleCtx() map[string]interface{} {
	return map[string]interface{}{
		"app_name": "faynosyncSparkleExample",
		"platform": "darwin",
		"arch":     "arm64",
		"channel":  "nightly",
		"version":  "0.0.1",
		"api_url":  "https://cdn",
	}
}

// The uploaded appcast must land on the exact S3 key the materializer writes to,
// so the managed feed overwrites the raw upload (no second, unmanaged appcast).
func TestSparkleAppcastKeyMatchesMaterializedKey(t *testing.T) {
	materialized := sparkle.AppcastObjectKey("admin", "faynosyncSparkleExample", "darwin", "arm64", "nightly")

	for _, name := range []string{"appcast.nightly.xml", "appcast.xml", "APPCAST.NIGHTLY.XML"} {
		_, s3Key := BuildS3Key(sparkleCtx(), "admin", "new.xml", name, sparkle.UpdaterType)
		if s3Key != materialized {
			t.Errorf("appcast %q -> key %q, want materialized key %q", name, s3Key, materialized)
		}
	}
}

func TestSparkleArchiveKeyIsFlat(t *testing.T) {
	_, s3Key := BuildS3Key(sparkleCtx(), "admin", "new.zip", "faynosyncSparkleExample-0.0.1.zip", sparkle.UpdaterType)
	want := "sparkle/admin/faynosyncSparkleExample/darwin/arm64/faynosyncSparkleExample-0.0.1.zip"
	if s3Key != want {
		t.Errorf("archive key = %q, want %q", s3Key, want)
	}
}
