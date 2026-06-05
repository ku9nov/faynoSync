package metadata

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

const (
	snapshotLockTTL          = 300 * time.Second
	snapshotLockMaxWait      = 500 * time.Second
	snapshotLockInitialDelay = 50 * time.Millisecond
	snapshotLockMaxDelay     = 2 * time.Second
	snapshotLockReleaseGrace = 5 * time.Second
)

var snapshotLockReleaseScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
	return redis.call("DEL", KEYS[1])
end
return 0
`)

func snapshotLockKey(adminName, appName string) string {
	return fmt.Sprintf("LOCK_SNAPSHOT_%s_%s", adminName, appName)
}

func WithSnapshotLock(
	ctx context.Context,
	redisClient *redis.Client,
	adminName string,
	appName string,
	fn func() error,
) error {
	if redisClient == nil {
		return fmt.Errorf("redis client is required to acquire snapshot lock")
	}

	lockKey := snapshotLockKey(adminName, appName)
	token := uuid.New().String()

	lockCtx, cancel := context.WithTimeout(ctx, snapshotLockMaxWait)
	defer cancel()

	delay := snapshotLockInitialDelay
	for {
		acquired, err := redisClient.SetNX(lockCtx, lockKey, token, snapshotLockTTL).Result()
		if err != nil {
			if lockCtx.Err() != nil {
				return fmt.Errorf("failed to acquire snapshot lock %s: timeout after %v (another update is in progress)", lockKey, snapshotLockMaxWait)
			}
			return fmt.Errorf("failed to acquire snapshot lock %s: %w", lockKey, err)
		}
		if acquired {
			break
		}

		logrus.Debugf("Snapshot lock %s held by another process, retrying in %v", lockKey, delay)
		select {
		case <-lockCtx.Done():
			return fmt.Errorf("failed to acquire snapshot lock %s: timeout after %v (another update is in progress)", lockKey, snapshotLockMaxWait)
		case <-time.After(delay):
			delay *= 2
			if delay > snapshotLockMaxDelay {
				delay = snapshotLockMaxDelay
			}
		}
	}

	defer func() {
		// Release with a fresh context so cancellation of ctx cannot leak the lock
		// (the TTL is only a backstop). Only release if we still own the token.
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), snapshotLockReleaseGrace)
		defer releaseCancel()
		if err := snapshotLockReleaseScript.Run(releaseCtx, redisClient, []string{lockKey}, token).Err(); err != nil && err != redis.Nil {
			logrus.Warnf("Failed to release snapshot lock %s: %v", lockKey, err)
		}
	}()

	return fn()
}
