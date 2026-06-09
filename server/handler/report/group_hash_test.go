package report

import (
	"crypto/sha256"
	"encoding/hex"
	"faynoSync/server/model"
	"testing"

	"github.com/stretchr/testify/assert"
)

func mkInputs() (model.ReportApplication, model.ReportSystem, model.ReportEvent) {
	return model.ReportApplication{Name: "my-app", Version: "1.4.2", Channel: "stable"},
		model.ReportSystem{Platform: "windows", Arch: "amd64"},
		model.ReportEvent{Type: "update_failure", Reason: "checksum_mismatch"}
}

func TestBuildGroupHashStable(t *testing.T) {
	app, system, event := mkInputs()
	h1 := buildGroupHash(app, system, event)
	h2 := buildGroupHash(app, system, event)
	assert.Equal(t, h1, h2, "same input must produce the same hash")

	want := sha256.Sum256([]byte("my-app|1.4.2|stable|windows|amd64|update_failure|checksum_mismatch"))
	assert.Equal(t, hex.EncodeToString(want[:]), h1)
	assert.Len(t, h1, 64)
}

func TestBuildGroupHashSeparatorSafety(t *testing.T) {
	// Without the "|" separator, ("ab","1") and ("a","b1") would collide.
	a := buildGroupHash(
		model.ReportApplication{Name: "ab", Version: "1", Channel: "stable"},
		model.ReportSystem{Platform: "windows", Arch: "amd64"},
		model.ReportEvent{Type: "crash", Reason: "x"},
	)
	b := buildGroupHash(
		model.ReportApplication{Name: "a", Version: "b1", Channel: "stable"},
		model.ReportSystem{Platform: "windows", Arch: "amd64"},
		model.ReportEvent{Type: "crash", Reason: "x"},
	)
	assert.NotEqual(t, a, b, "separator must prevent field-boundary collisions")
}

func TestBuildGroupHashDimensionsMatter(t *testing.T) {
	app, system, event := mkInputs()
	base := buildGroupHash(app, system, event)

	variants := []func(*model.ReportApplication, *model.ReportSystem, *model.ReportEvent){
		func(a *model.ReportApplication, _ *model.ReportSystem, _ *model.ReportEvent) { a.Name = "other-app" },
		func(a *model.ReportApplication, _ *model.ReportSystem, _ *model.ReportEvent) { a.Version = "1.4.3" },
		func(a *model.ReportApplication, _ *model.ReportSystem, _ *model.ReportEvent) { a.Channel = "beta" },
		func(_ *model.ReportApplication, s *model.ReportSystem, _ *model.ReportEvent) { s.Platform = "linux" },
		func(_ *model.ReportApplication, s *model.ReportSystem, _ *model.ReportEvent) { s.Arch = "arm64" },
		func(_ *model.ReportApplication, _ *model.ReportSystem, e *model.ReportEvent) { e.Type = "crash" },
		func(_ *model.ReportApplication, _ *model.ReportSystem, e *model.ReportEvent) { e.Reason = "disk_full" },
	}

	for i, mutate := range variants {
		a, s, e := mkInputs()
		mutate(&a, &s, &e)
		assert.NotEqualf(t, base, buildGroupHash(a, s, e), "variant %d must change the hash", i)
	}
}
