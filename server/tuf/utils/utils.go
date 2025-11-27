package tuf_utils

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

func HelperExpireIn(days int) time.Time {
	return time.Now().AddDate(0, 0, days).UTC()
}

// helperGetPathForTarget returns local and target paths for target (?)
func HelperGetPathForTarget(name string) (string, string) {
	cwd, err := os.Getwd()
	if err != nil {
		panic(fmt.Sprintln("TUF:", "getting cwd failed", err))
	}

	return name, filepath.Join(cwd, name)
}

func GetExpirationFromRedis(redisClient *redis.Client, ctx context.Context, key string, defaultValue int) int {
	if redisClient == nil {
		return defaultValue
	}

	value, err := redisClient.Get(ctx, key).Int()
	if err != nil {
		logrus.Debugf("Failed to get %s from Redis, using default %d: %v", key, defaultValue, err)
		return defaultValue
	}

	return value
}

func CalculateExpirationDays(expiresStr string) int {
	expires, err := time.Parse(time.RFC3339, expiresStr)
	if err != nil {
		expires, err = time.Parse("2006-01-02T15:04:05.999999999Z", expiresStr)
		if err != nil {
			logrus.Warnf("Could not parse expiration date: %s, using default", expiresStr)
			return 365
		}
	}

	now := time.Now().UTC()
	diff := expires.Sub(now)
	days := int(diff.Hours() / 24)

	if days < 1 {
		days = 1
	}

	return days
}
