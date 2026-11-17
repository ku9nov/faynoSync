package info

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newHealthRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rc.Close() })
	return mr, rc
}

func TestHealthRedisDownIsUnhealthy(t *testing.T) {
	rc := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
	defer rc.Close()

	resp, code := runHealthChecks(context.Background(), nil, rc, viper.New())

	assert.Equal(t, http.StatusServiceUnavailable, code)
	assert.Equal(t, "unhealthy", resp.Status)
	assert.Equal(t, checkFail, resp.Checks["redis"].Status)
	assert.Equal(t, checkSkipped, resp.Checks["mongodb"].Status)
}

func TestHealthStorageFailureOnlyDegrades(t *testing.T) {
	_, rc := newHealthRedis(t)
	env := viper.New()
	env.Set("STORAGE_DRIVER", "nonexistent")

	resp, code := runHealthChecks(context.Background(), nil, rc, env)

	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "degraded", resp.Status)
	assert.Equal(t, checkOK, resp.Checks["redis"].Status)
	assert.Equal(t, checkFail, resp.Checks["storage"].Status)
	assert.Equal(t, checkSkipped, resp.Checks["tuf_bumper"].Status)
	require.NotNil(t, resp.Checks["redis"].LatencyMS)
	assert.Nil(t, resp.Checks["disk"].LatencyMS)
}

func TestHealthTUFBumperHeartbeat(t *testing.T) {
	mr, rc := newHealthRedis(t)
	env := viper.New()
	env.Set("TUF_ENABLED", true)
	ctx := context.Background()

	assert.Equal(t, checkFail, checkTUFBumper(ctx, rc, env), "never ran")

	require.NoError(t, mr.Set("TUF_ONLINE_BUMP_LAST_OK", time.Now().UTC().Format(time.RFC3339)))
	assert.Equal(t, checkOK, checkTUFBumper(ctx, rc, env))

	require.NoError(t, mr.Set("TUF_ONLINE_BUMP_LAST_OK", time.Now().UTC().Add(-11*time.Minute).Format(time.RFC3339)))
	assert.Equal(t, checkFail, checkTUFBumper(ctx, rc, env), "stale")
}
