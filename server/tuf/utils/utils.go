package tuf_utils

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"faynoSync/server/utils"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
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

func CalculatePathHash(path string) string {
	hash := sha256.Sum256([]byte(path))
	return hex.EncodeToString(hash[:])
}

func ExtractTUFPathFromLink(link string, checkAppVisibility bool, env *viper.Viper) (string, error) {
	if link == "" {
		return "", fmt.Errorf("link is empty")
	}

	s3Key, err := utils.ExtractS3Key(link, checkAppVisibility, env)
	if err != nil {
		logrus.Errorf("Failed to extract S3 key from link: %v", err)
		return "", fmt.Errorf("failed to extract S3 key from link: %w", err)
	}

	logrus.Debugf("Extracted TUF path from link: %s -> %s", link, s3Key)

	return s3Key, nil
}
