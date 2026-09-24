package create

import (
	"context"
	"testing"

	"github.com/spf13/viper"
)

// Nothing that changed no published state and no feed may reach Mongo, Redis or
// storage: a nil database and client here stand in for "must not be touched".
func TestFinalizeUploadTouchesNothingWithoutPublishOrFeed(t *testing.T) {
	ctxQueryMap := map[string]interface{}{
		"app_name": "MyApp",
		"channel":  "nightly",
		"platform": "darwin",
		"arch":     "arm64",
		"updater":  "tauri",
	}

	FinalizeUpload(
		context.Background(),
		nil,
		nil,
		false,
		ctxQueryMap,
		"acme",
		"MyApp",
		[]string{"MyApp-1.0.0.tar.gz"},
		true,
		viper.New(),
	)
}

// Only an explicit publish flag may invalidate caches: anything else is either a
// different edit or a value the API never accepted as a boolean.
func TestExplicitPublishValue(t *testing.T) {
	cases := []struct {
		name      string
		params    map[string]interface{}
		wantValue string
		wantSet   bool
	}{
		{"published", map[string]interface{}{"publish": "true"}, "true", true},
		{"unpublished", map[string]interface{}{"publish": "false"}, "false", true},
		{"uppercase and padded", map[string]interface{}{"publish": " TRUE "}, "true", true},
		{"absent", map[string]interface{}{}, "", false},
		{"empty", map[string]interface{}{"publish": ""}, "", false},
		{"numeric", map[string]interface{}{"publish": "1"}, "1", false},
		{"not a string", map[string]interface{}{"publish": true}, "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value, set := explicitPublishValue(tc.params)
			if value != tc.wantValue || set != tc.wantSet {
				t.Errorf("explicitPublishValue() = %q/%v, want %q/%v", value, set, tc.wantValue, tc.wantSet)
			}
		})
	}
}
