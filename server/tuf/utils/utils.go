package tuf_utils

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"faynoSync/server/utils"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// validAppNameRe allows alphanumeric characters and hyphens only.
// Underscores are intentionally excluded: the Redis key separator is "_",
// so allowing "_" in appName would allow key collisions between different
// admin/app combinations (e.g. admin="a_b" + app="c" vs admin="a" + app="b_c").
var validAppNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]*$`)

// ValidateAppName returns an error if appName contains characters that
// could cause Redis key collisions or S3 path injection.
func ValidateAppName(appName string) error {
	if !validAppNameRe.MatchString(appName) {
		return fmt.Errorf("appName %q is invalid: only alphanumeric characters and hyphens are allowed, and it must start with an alphanumeric character", appName)
	}
	return nil
}

// Expiration bounds (in days).
// timestamp <= snapshot <= targets <= root: root is the offline trust anchor
const (
	MinExpirationDays = 1

	MaxRootExpirationDays      = 365
	MaxTargetsExpirationDays   = 180
	MaxSnapshotExpirationDays  = 30
	MaxTimestampExpirationDays = 7
	MaxDelegatedExpirationDays = 180
)

func MaxExpirationDaysForRole(role string) int {
	switch strings.ToLower(role) {
	case "root":
		return MaxRootExpirationDays
	case "targets":
		return MaxTargetsExpirationDays
	case "snapshot":
		return MaxSnapshotExpirationDays
	case "timestamp":
		return MaxTimestampExpirationDays
	default:
		return MaxDelegatedExpirationDays
	}
}

func ValidateExpiration(role string, days int) error {
	if days < MinExpirationDays {
		return fmt.Errorf("expiration for role %q must be >= %d day(s), got %d", role, MinExpirationDays, days)
	}
	if max := MaxExpirationDaysForRole(role); days > max {
		return fmt.Errorf("expiration for role %q must be <= %d days, got %d", role, max, days)
	}
	return nil
}

func HelperExpireIn(days int) time.Time {
	return time.Now().AddDate(0, 0, days).UTC()
}

// HelperGetPathForTarget returns local and target paths for the named target.
func HelperGetPathForTarget(name string) (string, string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", "", fmt.Errorf("getting cwd failed: %w", err)
	}

	return name, filepath.Join(cwd, name), nil
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

func CalculateExpirationDays(expiresStr string) (int, error) {
	expires, err := time.Parse(time.RFC3339, expiresStr)
	if err != nil {
		expires, err = time.Parse("2006-01-02T15:04:05.999999999Z", expiresStr)
		if err != nil {
			return 0, fmt.Errorf("could not parse expiration date %q: %w", expiresStr, err)
		}
	}

	now := time.Now().UTC()
	diff := expires.Sub(now)
	days := int(diff.Hours() / 24)

	if days < 1 {
		days = 1
	}

	return days, nil
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
