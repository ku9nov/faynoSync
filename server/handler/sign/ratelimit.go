package sign

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

const (
	loginPerIPPerMinute       int64 = 10
	loginPerUsernamePerMinute int64 = 5
	signupPerIPPerHour        int64 = 5
	signupGlobalPerHour       int64 = 20
)

type rateLimit struct {
	key    string
	limit  int64
	window time.Duration
}

func (l rateLimit) bucketKey(now time.Time) string {
	return fmt.Sprintf("%s:%d", l.key, now.Unix()/int64(l.window/time.Second))
}

func loginIPLimit(c *gin.Context) rateLimit {
	return rateLimit{"auth:rl:login:ip:" + clientIPKey(c), loginPerIPPerMinute, time.Minute}
}

func loginUsernameLimit(username string) rateLimit {
	sum := sha256.Sum256([]byte(username))
	return rateLimit{"auth:rl:login:user:" + hex.EncodeToString(sum[:]), loginPerUsernamePerMinute, time.Minute}
}

func signupIPLimit(c *gin.Context) rateLimit {
	return rateLimit{"auth:rl:signup:ip:" + clientIPKey(c), signupPerIPPerHour, time.Hour}
}

var timeNow = time.Now

var signupGlobalLimit = rateLimit{"auth:rl:signup:global", signupGlobalPerHour, time.Hour}

// A single IPv6 host usually controls a whole /64, so per-address buckets would be trivially rotated.
func clientIPKey(c *gin.Context) string {
	ip := net.ParseIP(c.ClientIP())
	if ip == nil {
		return c.ClientIP()
	}
	if ip.To4() == nil {
		return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
	return ip.String()
}

// enforceRateLimits fails closed on a Redis error: these limits are the only brute-force
// protection for accounts that can publish server-signed artifacts.
func enforceRateLimits(c *gin.Context, rdb *redis.Client, limits []rateLimit, now time.Time) bool {
	if rdb == nil {
		return true
	}

	ctx := c.Request.Context()
	for _, l := range limits {
		key := l.bucketKey(now)
		count, err := rdb.Incr(ctx, key).Result()
		if err != nil {
			logrus.Errorf("Auth rate limit check failed (rejecting request): %v", err)
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "service temporarily unavailable"})
			return false
		}
		if count == 1 {
			rdb.Expire(ctx, key, l.window)
		}
		if count > l.limit {
			windowSeconds := int64(l.window / time.Second)
			retryAfter := windowSeconds - now.Unix()%windowSeconds
			logrus.Warnf("Auth rate limit exceeded for %s from IP %s", l.key, c.ClientIP())
			c.Header("Retry-After", strconv.FormatInt(retryAfter, 10))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "too many attempts, try again later"})
			return false
		}
	}

	return true
}

func resetRateLimit(ctx context.Context, rdb *redis.Client, l rateLimit, now time.Time) {
	if rdb == nil {
		return
	}
	if err := rdb.Del(ctx, l.bucketKey(now)).Err(); err != nil {
		logrus.Errorf("Failed to reset auth rate limit for %s: %v", l.key, err)
	}
}
