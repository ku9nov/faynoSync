package info

import (
	"context"
	"testing"

	"faynoSync/server/utils"

	"github.com/spf13/viper"
)

// Embedding a nil interface makes any storage call panic, so a private app that
// reaches the writer fails the test instead of silently passing.
type panicStorageClient struct {
	utils.StorageClient
}

func TestMaterializeSkipsPrivateApps(t *testing.T) {
	ctx := context.Background()
	env := viper.New()
	env.Set("S3_BUCKET_NAME", "public")
	store := panicStorageClient{}
	tuples := []FeedTuple{{Channel: "nightly", Platform: "windows", Arch: "x64"}}

	cases := map[string]func() error{
		"velopack full": func() error { return MaterializeVelopackFeeds(ctx, nil, store, env, "acme", "MyApp", true) },
		"velopack tuples": func() error {
			return MaterializeVelopackFeedsForTuples(ctx, nil, store, env, "acme", "MyApp", tuples, true)
		},
		"sparkle full": func() error { return MaterializeSparkleFeeds(ctx, nil, store, env, "acme", "MyApp", true) },
		"sparkle tuples": func() error {
			return MaterializeSparkleFeedsForTuples(ctx, nil, store, env, "acme", "MyApp", tuples, true)
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			if err := run(); err != nil {
				t.Fatalf("private app materialization returned %v, want no-op", err)
			}
		})
	}
}
