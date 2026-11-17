package info

import (
	"context"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"

	"faynoSync/server/tuf/metadata"
	"faynoSync/server/utils"
	"faynoSync/server/utils/storage"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	healthCheckTimeout = 3 * time.Second
	// /health is public: without a cache every anonymous request fans out to Mongo, Redis and S3.
	healthCacheTTL    = 10 * time.Second
	healthMinFreeDisk = 1 << 30

	checkOK      = "ok"
	checkFail    = "fail"
	checkSkipped = "skipped"
)

type healthCheckResult struct {
	Status    string `json:"status"`
	LatencyMS *int64 `json:"latency_ms,omitempty"`
}

type healthResponse struct {
	Status string                       `json:"status"`
	Checks map[string]healthCheckResult `json:"checks"`
}

var (
	healthCacheMu   sync.Mutex
	healthCached    healthResponse
	healthCachedAt  time.Time
	healthCacheCode int
)

func HealthCheck(c *gin.Context, mongoClient *mongo.Client, redisClient *redis.Client) {
	// Held while probing so concurrent requests wait for one run instead of stampeding.
	healthCacheMu.Lock()
	defer healthCacheMu.Unlock()

	if time.Since(healthCachedAt) >= healthCacheTTL {
		healthCached, healthCacheCode = runHealthChecks(c.Request.Context(), mongoClient, redisClient, viper.GetViper())
		healthCachedAt = time.Now()
	}
	c.JSON(healthCacheCode, healthCached)
}

func runHealthChecks(parent context.Context, mongoClient *mongo.Client, redisClient *redis.Client, env *viper.Viper) (healthResponse, int) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), healthCheckTimeout)
	defer cancel()

	probes := map[string]func(context.Context) string{
		"mongodb": func(ctx context.Context) string { return checkMongo(ctx, mongoClient) },
		"redis":   func(ctx context.Context) string { return checkRedis(ctx, redisClient) },
		"storage": func(ctx context.Context) string { return checkStorage(ctx, env) },
		"disk":    func(context.Context) string { return checkDisk() },
		"tuf_bumper": func(ctx context.Context) string {
			return checkTUFBumper(ctx, redisClient, env)
		},
	}
	timed := map[string]bool{"mongodb": true, "redis": true, "storage": true}

	checks := make(map[string]healthCheckResult, len(probes))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for name, probe := range probes {
		wg.Add(1)
		go func(name string, probe func(context.Context) string) {
			defer wg.Done()
			start := time.Now()
			result := healthCheckResult{Status: probe(ctx)}
			if timed[name] && result.Status != checkSkipped {
				ms := time.Since(start).Milliseconds()
				result.LatencyMS = &ms
			}
			mu.Lock()
			checks[name] = result
			mu.Unlock()
		}(name, probe)
	}
	wg.Wait()

	resp := healthResponse{Status: "healthy", Checks: checks}
	for name, result := range checks {
		if result.Status != checkFail {
			continue
		}
		// Only the stores every request depends on take the instance out; the rest
		// degrade features (uploads, re-signing) while update checks keep working.
		if name == "mongodb" || name == "redis" {
			resp.Status = "unhealthy"
			return resp, http.StatusServiceUnavailable
		}
		resp.Status = "degraded"
	}
	return resp, http.StatusOK
}

func checkMongo(ctx context.Context, mongoClient *mongo.Client) string {
	if mongoClient == nil {
		return checkSkipped
	}
	if err := mongoClient.Ping(ctx, nil); err != nil {
		logrus.Error("MongoDB connection error: ", err)
		return checkFail
	}
	return checkOK
}

func checkRedis(ctx context.Context, redisClient *redis.Client) string {
	if redisClient == nil {
		return checkSkipped
	}
	if err := redisClient.Ping(ctx).Err(); err != nil {
		logrus.Error("Redis connection error: ", err)
		return checkFail
	}
	return checkOK
}

func checkStorage(ctx context.Context, env *viper.Viper) string {
	client, err := utils.NewStorageFactory(env).CreateStorageClient()
	if err != nil {
		logrus.Errorf("Health check: failed to create storage client: %v", err)
		return checkFail
	}
	checker, ok := client.(storage.BucketChecker)
	if !ok {
		return checkSkipped
	}

	seen := map[string]bool{}
	for _, key := range []string{"S3_BUCKET_NAME", "S3_BUCKET_NAME_PRIVATE", "S3_BUCKET_NAME_CDN"} {
		bucket := env.GetString(key)
		if bucket == "" || seen[bucket] {
			continue
		}
		seen[bucket] = true
		if err := checker.CheckBucket(ctx, bucket); err != nil {
			logrus.Errorf("Health check: storage bucket %s (%s) unreachable: %v", bucket, key, err)
			return checkFail
		}
	}
	return checkOK
}

// Multipart uploads and feed downloads spool to the temp dir.
func checkDisk() string {
	dir := os.TempDir()
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		logrus.Errorf("Health check: statfs %s failed: %v", dir, err)
		return checkFail
	}
	free := uint64(st.Bavail) * uint64(st.Bsize)
	if free < healthMinFreeDisk {
		logrus.Errorf("Health check: low disk space in %s: %d bytes free, need %d", dir, free, healthMinFreeDisk)
		return checkFail
	}
	return checkOK
}

func checkTUFBumper(ctx context.Context, redisClient *redis.Client, env *viper.Viper) string {
	if !env.GetBool("TUF_ENABLED") || redisClient == nil {
		return checkSkipped
	}
	last, err := metadata.LastOnlineBump(ctx, redisClient)
	if err != nil {
		logrus.Errorf("Health check: failed to read TUF online bump heartbeat: %v", err)
		return checkFail
	}
	if last.IsZero() {
		logrus.Errorf("Health check: TUF online bumper has never completed a tick")
		return checkFail
	}
	if age := time.Since(last); age > metadata.OnlineBumpStaleAfter {
		logrus.Errorf("Health check: TUF online bumper last completed %s ago (limit %s)", age.Round(time.Second), metadata.OnlineBumpStaleAfter)
		return checkFail
	}
	return checkOK
}
