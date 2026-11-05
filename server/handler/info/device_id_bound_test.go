package info

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const maxStoredDeviceIDLen = 128

// X-Device-ID is an anonymous header kept in up to six 30-day sets; it must not be stored unbounded.
func assertNoOversizedSetMember(t *testing.T, mr *miniredis.Miniredis) {
	t.Helper()
	sets := 0
	for _, key := range mr.Keys() {
		if mr.Type(key) != "set" {
			continue
		}
		sets++
		members, err := mr.Members(key)
		require.NoError(t, err)
		for _, m := range members {
			assert.LessOrEqual(t, len(m), maxStoredDeviceIDLen, "set %s stores a %d-byte member", key, len(m))
		}
	}
	t.Logf("checked %d sets", sets)
}

func longDeviceID() string { return strings.Repeat("d", 64<<10) }

// To verify: In trackClientTelemetryWithLatest store the raw X-Device-ID; test will fail (64 KB member).
func TestTelemetryBeacon_LongDeviceID_NotStoredRaw(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	idx := NewTelemetryAllowList()
	idx.Add("o", "a", "stable", "linux", "x64", "1.0.0")
	prev := telemetryAllowList.Swap(idx)
	t.Cleanup(func() { telemetryAllowList.Store(prev) })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/telemetry/beacon", func(c *gin.Context) { TelemetryBeacon(c, rdb) })
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/telemetry/beacon?owner=o&app_name=a&version=1.0.0&channel=stable&platform=linux&arch=x64&is_latest=false", nil)
	req.Header.Set("X-Device-ID", longDeviceID())
	router.ServeHTTP(w, req)

	assertNoOversizedSetMember(t, mr)
}

// /checkVersion reaches the same sink through logStatsToRedis.
// To verify: In trackClientTelemetry store the raw X-Device-ID; test will fail (64 KB member).
func TestCheckVersionTelemetry_LongDeviceID_NotStoredRaw(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	prev := viper.GetBool("ENABLE_TELEMETRY")
	viper.Set("ENABLE_TELEMETRY", true)
	t.Cleanup(func() { viper.Set("ENABLE_TELEMETRY", prev) })

	logStatsToRedis(context.Background(), rdb, map[string]interface{}{
		"owner": "o", "app_name": "a", "version": "1.0.0", "channel": "stable", "platform": "linux", "arch": "x64",
	}, true, longDeviceID())

	assertNoOversizedSetMember(t, mr)
}
