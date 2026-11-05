package info

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTelemetry_ChannelSwitch_CountsDeviceOnceSameDay(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	ctx := context.Background()

	track := func(deviceID, channel, version string) {
		trackClientTelemetry(ctx, rdb, map[string]interface{}{
			"owner": "o", "app_name": "a", "version": version, "channel": channel, "platform": "linux", "arch": "x64",
		}, false, deviceID)
	}
	track("d1", "stable", "1.0.0")
	track("d2", "stable", "1.0.0")
	track("d1", "beta", "1.1.0")

	date := time.Now().UTC().Format("2006-01-02")
	members := func(channel string) []string {
		key := fmt.Sprintf("stats:o:a:channels:%s:%s", date, channel)
		if !mr.Exists(key) {
			return nil
		}
		m, err := mr.Members(key)
		require.NoError(t, err)
		return m
	}
	assert.ElementsMatch(t, []string{"d2"}, members("stable"))
	assert.ElementsMatch(t, []string{"d1"}, members("beta"))

	track("d1", "stable", "1.0.0")
	assert.ElementsMatch(t, []string{"d1", "d2"}, members("stable"))
	assert.Empty(t, members("beta"))
}
