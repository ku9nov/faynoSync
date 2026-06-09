package report

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	rlGroupPerMinute      int64 = 30
	rlDevicePerHour       int64 = 1
	defaultRLKeyPerMinute int64 = 100
)

// checkRateLimits reports whether the request is within all rate limits.
// Counters are fixed-window (per-minute / per-hour buckets). The report key and
// device id are used only as Redis keys, never persisted. On a Redis error it
// fails open and logs: rate limiting is abuse control, not a trust boundary, so
// a Redis blip must not drop legitimate reports.
func checkRateLimits(ctx context.Context, rdb *redis.Client, reportKey, deviceID, groupHash string, now time.Time) bool {
	if rdb == nil {
		return true
	}

	keyPerMinute := viper.GetInt64("REPORTS_RATE_LIMIT_PER_KEY_PER_MINUTE")
	if keyPerMinute <= 0 {
		keyPerMinute = defaultRLKeyPerMinute
	}

	minuteBucket := now.Unix() / 60
	hourBucket := now.Unix() / 3600

	limits := []struct {
		key    string
		limit  int64
		window time.Duration
	}{
		{fmt.Sprintf("reports:rl:key:%s:minute:%d", reportKey, minuteBucket), keyPerMinute, time.Minute},
		{fmt.Sprintf("reports:rl:device:%s:group:%s:hour:%d", deviceID, groupHash, hourBucket), rlDevicePerHour, time.Hour},
		{fmt.Sprintf("reports:rl:group:%s:minute:%d", groupHash, minuteBucket), rlGroupPerMinute, time.Minute},
	}

	for _, l := range limits {
		count, err := rdb.Incr(ctx, l.key).Result()
		if err != nil {
			logrus.Errorf("Report rate limit check failed (allowing request): %v", err)
			return true
		}
		if count == 1 {
			rdb.Expire(ctx, l.key, l.window)
		}
		if count > l.limit {
			return false
		}
	}

	return true
}
