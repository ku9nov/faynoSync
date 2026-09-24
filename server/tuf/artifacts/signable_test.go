package artifacts

import (
	"testing"

	"faynoSync/server/model"
)

func TestSelectSignableArtifacts(t *testing.T) {
	artifacts := []model.Artifact{
		{Link: "pkg-unsigned.nupkg"},
		{Link: "pkg-signed.nupkg", TufSigned: true},
		{Link: "releases.nightly.json", IsFeed: true},
		{Link: "delta.nupkg"},
	}

	got := selectSignableArtifacts(artifacts)

	want := []string{"pkg-unsigned.nupkg", "delta.nupkg"}
	if len(got) != len(want) {
		t.Fatalf("got %d artifacts, want %d: %+v", len(got), len(want), got)
	}
	for i, link := range want {
		if got[i].Link != link {
			t.Errorf("artifact %d = %q, want %q", i, got[i].Link, link)
		}
	}
}

// A feed already marked tuf_signed (pre-split data) must still be excluded, so a
// backfill cannot be defeated by a stale flag.
func TestSelectSignableArtifacts_SignedFeedStillExcluded(t *testing.T) {
	got := selectSignableArtifacts([]model.Artifact{
		{Link: "appcast.xml", IsFeed: true, TufSigned: true},
	})
	if len(got) != 0 {
		t.Fatalf("expected no signable artifacts, got %+v", got)
	}
}

// Feed-only versions are a normal state, not an error: the caller must see an
// empty slice rather than fall through to signing.
func TestSelectSignableArtifacts_FeedOnly(t *testing.T) {
	got := selectSignableArtifacts([]model.Artifact{
		{Link: "latest.yml", IsFeed: true},
	})
	if len(got) != 0 {
		t.Fatalf("expected no signable artifacts, got %+v", got)
	}
}

// Artifacts stored before is_feed existed have the field absent (bson omitempty),
// which decodes to false — they stay signable, preserving current behaviour.
func TestSelectSignableArtifacts_LegacyArtifactsStaySignable(t *testing.T) {
	got := selectSignableArtifacts([]model.Artifact{
		{Link: "legacy.exe"},
	})
	if len(got) != 1 {
		t.Fatalf("expected legacy artifact to stay signable, got %+v", got)
	}
}
