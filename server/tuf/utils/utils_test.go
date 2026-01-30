package tuf_utils

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
)

func TestGetExpirationFromRedis_ReturnsRedisValue(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	mr.Set("ROOT_EXPIRATION_owner_appName", "180")

	result := GetExpirationFromRedis(client, ctx, "ROOT_EXPIRATION_owner_appName", 365)

	assert.Equal(t, 180, result)
}

func TestGetExpirationFromRedis_NilClient(t *testing.T) {
	ctx := context.Background()
	var redisClient *redis.Client = nil
	key := "ROOT_EXPIRATION_owner_appName"
	defaultValue := 365

	result := GetExpirationFromRedis(redisClient, ctx, key, defaultValue)

	assert.Equal(t, defaultValue, result, "Result should equal default value when Redis client is nil")
}

func TestGetExpirationFromRedis_ValidClient(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	key := "ROOT_EXPIRATION_owner_appName"
	expectedValue := 180
	defaultValue := 365
	mr.Set(key, "180")

	result := GetExpirationFromRedis(client, ctx, key, defaultValue)

	assert.Equal(t, expectedValue, result, "Result should equal Redis value when key exists")
}

func TestGetExpirationFromRedis_RedisError(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	key := "ROOT_EXPIRATION_owner_appName"
	defaultValue := 365

	mr.Close()

	result := GetExpirationFromRedis(client, ctx, key, defaultValue)

	assert.Equal(t, defaultValue, result, "Result should equal default value when Redis returns error")
}

func TestGetExpirationFromRedis_RedisNil(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	key := "ROOT_EXPIRATION_owner_appName:not:exists"
	defaultValue := 365

	result := GetExpirationFromRedis(client, ctx, key, defaultValue)

	assert.Equal(t, defaultValue, result, "Result should equal default value when key doesn't exist")
}

// To verify: Modify CalculateExpirationDays to return 0
func TestCalculateExpirationDays_ValidRFC3339(t *testing.T) {

	futureDate := time.Now().AddDate(0, 0, 30).UTC()
	expiresStr := futureDate.Format(time.RFC3339)
	expectedDays := 30

	result := CalculateExpirationDays(expiresStr)

	assert.GreaterOrEqual(t, result, expectedDays-1, "Result should be at least %d days", expectedDays-1)
	assert.LessOrEqual(t, result, expectedDays+1, "Result should be at most %d days", expectedDays+1)
}

// To verify: Modify CalculateExpirationDays to return 365
func TestCalculateExpirationDays_ValidAlternativeFormat(t *testing.T) {

	futureDate := time.Now().AddDate(0, 0, 60).UTC()
	expiresStr := futureDate.Format("2006-01-02T15:04:05.999999999Z")
	expectedDays := 60

	result := CalculateExpirationDays(expiresStr)

	assert.GreaterOrEqual(t, result, expectedDays-1, "Result should be at least %d days", expectedDays-1)
	assert.LessOrEqual(t, result, expectedDays+1, "Result should be at most %d days", expectedDays+1)
}

// To verify: Modify CalculateExpirationDays to return 0
func TestCalculateExpirationDays_InvalidFormat(t *testing.T) {

	expiresStr := "invalid-date-format"
	defaultValue := 365

	result := CalculateExpirationDays(expiresStr)

	assert.Equal(t, defaultValue, result, "Result should be default value for invalid date format")
}

// To verify: Modify CalculateExpirationDays to return 0
func TestCalculateExpirationDays_PastDate(t *testing.T) {

	pastDate := time.Now().AddDate(0, 0, -10).UTC()
	expiresStr := pastDate.Format(time.RFC3339)

	result := CalculateExpirationDays(expiresStr)

	assert.GreaterOrEqual(t, result, 1, "Result should be at least 1 day for past dates")
}

// To verify: Modify CalculateExpirationDays to return 0
func TestCalculateExpirationDays_ZeroDays(t *testing.T) {

	now := time.Now().UTC()
	expiresStr := now.Format(time.RFC3339)

	result := CalculateExpirationDays(expiresStr)

	assert.GreaterOrEqual(t, result, 1, "Result should be at least 1 day even when calculated as 0")
}

// To verify: Modify CalculatePathHash to return "wrong-hash"
func TestCalculatePathHash_ValidPath(t *testing.T) {

	path := "test/path/to/file.json"

	result := CalculatePathHash(path)

	assert.NotEmpty(t, result, "Result should not be empty")
	assert.Len(t, result, 64, "SHA256 hash should be 64 hex characters")

	for _, char := range result {
		assert.Contains(t, "0123456789abcdef", string(char), "Hash should contain only hex characters")
	}

}

// To verify: Modify CalculatePathHash to return "non-empty"
func TestCalculatePathHash_EmptyPath(t *testing.T) {

	path := ""

	result := CalculatePathHash(path)

	assert.NotEmpty(t, result, "Result should not be empty even for empty path")
	assert.Len(t, result, 64, "SHA256 hash should be 64 hex characters")

	// Empty string SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	expectedEmptyHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	assert.Equal(t, expectedEmptyHash, result, "Hash of empty string should match expected value")
}

// To verify: Modify CalculatePathHash to add random value
func TestCalculatePathHash_ConsistentHash(t *testing.T) {

	path := "consistent/test/path"

	result1 := CalculatePathHash(path)
	result2 := CalculatePathHash(path)

	assert.Equal(t, result1, result2, "Hash should be consistent for the same path")
}
